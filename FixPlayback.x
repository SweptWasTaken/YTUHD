// Adapted from YouPiP by PoomSmart
// Updated for YouTube 21.20.4
//
// Root cause (confirmed via HAR + binary analysis):
//
//   YouTube on iOS uses SABR (Server-Driven ABR) via HAMPlayer.  SABR requires
//   a PO (Proof of Origin) token minted via Apple AppAttest.  LiveContainer2
//   re-signs YouTube with Team ID LSMHR68PG6 — not YouTube's real Team ID —
//   so every AppAttest exchange returns 400.  GVS responds to OnesieRequests
//   with a missing/empty poToken with STREAM_PROTECTION_STATUS=3, producing
//   Code=14 "Something went wrong".
//
//   ALL DASH codecs are 403'd because every DASH URL embeds spc= (Stream
//   Protection Context) signed with the empty PO token at player-request time.
//
// Fix: spoof the InnerTube client to ANDROID_VR (Oculus Quest, client ID 28).
//
//   ANDROID_VR DASH streams are currently exempt from PO token enforcement on
//   GVS.  HAMPlayer handles DASH natively; no AVPlayer or HLS injection is
//   needed.
//
//   The client swap is applied at three layers:
//     1. NSMutableURLRequest setHTTPBody: hook — deserializes the JSON body for
//        /player, /next, and /browse requests, rewrites context.client to
//        ANDROID_VR, and re-serializes.  This fires at the ObjC layer before
//        the body is handed to Cronet, so ALL requests are covered regardless
//        of which HTTP stack (Cronet, NSURLSession) carries them.  Also
//        persists visitorData across sessions for consistency, and captures
//        the OAuth Bearer token for PO token substitution.
//     2. NSMutableURLRequest setValue:forHTTPHeaderField: hook — rewrites
//        X-YouTube-Client-Name/Version headers and captures Authorization.
//     3. ObjC runtime sweep — replaces YTIClientInfo.clientName (int32 proto
//        getter, IOS=5 → ANDROID_VR=28) on all YTI-prefixed classes.  Belt-
//        and-suspenders for any code path that reads the proto object directly.
//
//   SABR is disabled (useServerDrivenAbr=NO) to prevent OnesieRequests entirely.
//   Anti-abuse and att/get intercepts remain active.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <os/lock.h>
#import <YouTubeHeader/MLAVPlayer.h>
#import <YouTubeHeader/MLDefaultPlayerViewFactory.h>
#import <YouTubeHeader/MLHLSMasterPlaylist.h>
#import <YouTubeHeader/MLHLSStreamSelector.h>
#import <YouTubeHeader/MLPlayerPool.h>
#import <YouTubeHeader/MLPlayerPoolImpl.h>
#import <YouTubeHeader/MLVideoDecoderFactory.h>
#import <YouTubeHeader/YTHotConfig.h>
#import "Header.h"

extern BOOL FixPlayback();

@interface YTGLMediaPlayerViewFactory : NSObject
@end

@interface YTIOSGuardSnapshotControllerImpl : NSObject
@end

@interface IGDPOTokenMinter : NSObject
@end

@interface iOSGuardManager : NSObject
@end

// ---------------------------------------------------------------------------
// Session state — visitorData and OAuth token persistence
//
// visitorData: extracted from every outgoing InnerTube request body and stored
// in NSUserDefaults.  Reinjected into subsequent requests so the server sees
// a consistent ANDROID_VR session identity across video navigations.
//
// oauthToken: the raw Bearer token extracted from Authorization headers.
// Returned by IGDPOTokenMinter as a substitute PO token — prevents the "no
// token" SABR grace timer from firing if ANDROID_VR ever receives SABR.
// ---------------------------------------------------------------------------

static NSString *YTUHDGetVisitorData(void) {
    return [[NSUserDefaults standardUserDefaults] stringForKey:@"ytuhd_visitorData"] ?: @"";
}

static void YTUHDSetVisitorData(NSString *vd) {
    if (vd.length)
        [[NSUserDefaults standardUserDefaults] setObject:vd forKey:@"ytuhd_visitorData"];
}

static NSData *YTUHDGetOAuthTokenData(void) {
    NSString *t = [[NSUserDefaults standardUserDefaults] stringForKey:@"ytuhd_oauth"];
    return t.length ? [t dataUsingEncoding:NSUTF8StringEncoding] : [NSData data];
}

static void YTUHDSetOAuthToken(NSString *token) {
    if (token.length)
        [[NSUserDefaults standardUserDefaults] setObject:token forKey:@"ytuhd_oauth"];
}

static BOOL YTUHDIsPlayerPath(NSString *path) {
    return [path containsString:@"/player"]
        || [path containsString:@"/next"]
        || [path containsString:@"/browse"];
}

// Returns an ANDROID_VR client dictionary using the best available visitorData.
static NSDictionary *YTUHDClientContext(NSString *visitorData) {
    NSMutableDictionary *c = [NSMutableDictionary dictionaryWithDictionary:@{
        @"clientName":        @"ANDROID_VR",
        @"clientVersion":     @"1.65.10",
        @"deviceMake":        @"Oculus",
        @"deviceModel":       @"Quest 3",
        @"androidSdkVersion": @32,
        @"osName":            @"Android",
        @"osVersion":         @"12L",
        @"hl":                @"en",
        @"gl":                @"US",
    }];
    NSString *vd = visitorData.length ? visitorData : YTUHDGetVisitorData();
    if (vd.length) c[@"visitorData"] = vd;
    return [c copy];
}

// ---------------------------------------------------------------------------
// Runtime diagnostic dump
//
// Written to Documents/ytuhd_<timestamp>.txt on every acquirePlayerForVideo.
// ---------------------------------------------------------------------------

static NSString *YTUHDDescribeValue(id val, int depth);

static NSString *YTUHDDescribeObject(id obj, int depth) {
    if (!obj) return @"nil";
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"[%@]", NSStringFromClass([obj class])];
    if (depth <= 0) return out;
    [out appendString:@"\n"];
    NSMutableSet *seen = [NSMutableSet set];
    for (Class cls = [obj class]; cls && cls != [NSObject class]; cls = [cls superclass]) {
        unsigned int n = 0;
        objc_property_t *list = class_copyPropertyList(cls, &n);
        for (unsigned int i = 0; i < n; i++) {
            NSString *name = @(property_getName(list[i]));
            if ([seen containsObject:name]) continue;
            [seen addObject:name];
            id val = nil;
            @try { val = [obj valueForKey:name]; }
            @catch (...) { [out appendFormat:@"  .%@ = <kvc-err>\n", name]; continue; }
            [out appendFormat:@"  .%@ = %@\n", name, YTUHDDescribeValue(val, depth - 1)];
        }
        free(list);
    }
    return out;
}

static NSString *YTUHDDescribeValue(id val, int depth) {
    if (!val)                                    return @"nil";
    if ([val isKindOfClass:[NSString class]])     return (NSString *)val;
    if ([val isKindOfClass:[NSNumber class]])     return [val stringValue];
    if ([val isKindOfClass:[NSURL class]])        return [(NSURL *)val absoluteString];
    if ([val isKindOfClass:[NSData class]])       return [NSString stringWithFormat:@"<Data %lu B>",
                                                       (unsigned long)[(NSData *)val length]];
    if ([val isKindOfClass:[NSArray class]]) {
        NSArray *a = val;
        if (!a.count) return @"[]";
        if (depth <= 0) return [NSString stringWithFormat:@"[%lu items]", (unsigned long)a.count];
        NSMutableString *r = [NSMutableString stringWithFormat:@"[%lu]\n", (unsigned long)a.count];
        NSUInteger lim = MIN(a.count, 5u);
        for (NSUInteger j = 0; j < lim; j++)
            [r appendFormat:@"    [%lu] %@\n", (unsigned long)j, YTUHDDescribeValue(a[j], depth - 1)];
        if (a.count > lim) [r appendFormat:@"    ...+%lu more\n", (unsigned long)(a.count - lim)];
        return r;
    }
    if ([val isKindOfClass:[NSDictionary class]])
        return [NSString stringWithFormat:@"<Dict %lu keys>", (unsigned long)[(NSDictionary *)val count]];
    if ([val isKindOfClass:[NSObject class]]) {
        if (depth <= 0) return [NSString stringWithFormat:@"[%@]", NSStringFromClass([val class])];
        NSString *inner = YTUHDDescribeObject(val, depth - 1);
        NSMutableString *indented = [NSMutableString string];
        for (NSString *line in [inner componentsSeparatedByString:@"\n"])
            if (line.length) [indented appendFormat:@"    %@\n", line];
        return [NSString stringWithFormat:@"\n%@", indented];
    }
    return [val description];
}

static NSString *ytuhd_timestamp(void) {
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"yyyy-MM-dd_HH-mm-ss";
    fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    return [fmt stringFromDate:[NSDate date]];
}

static void YTUHDDump(MLVideo *video, MLInnerTubePlayerConfig *config) {
    @try {
        NSMutableString *buf = [NSMutableString string];
        [buf appendFormat:@"YTUHD dump %@\n\n", [NSDate date]];
        [buf appendString:@"=== MLVideo ===\n"];
        [buf appendString:YTUHDDescribeObject(video,  3)];
        [buf appendString:@"\n=== MLInnerTubePlayerConfig ===\n"];
        [buf appendString:YTUHDDescribeObject(config, 3)];

        [buf appendString:@"\n=== Client Context Deep Probe ===\n"];
        @try {
            id pc = [config valueForKey:@"playerConfig"];
            if (!pc) pc = [config valueForKey:@"_playerConfig"];
            [buf appendFormat:@"playerConfig class: %@\n", NSStringFromClass([pc class])];
            for (NSString *key in @[@"context", @"clientContext", @"client",
                                    @"innerTubeContext", @"requestContext", @"clientInfo"]) {
                id ctx = nil;
                @try { ctx = [pc valueForKey:key]; } @catch (...) { continue; }
                if (!ctx) continue;
                [buf appendFormat:@"  .%@ = %@\n", key, YTUHDDescribeObject(ctx, 2)];
            }
            [buf appendString:@"\n  -- playerConfig full properties (depth 2) --\n"];
            [buf appendString:YTUHDDescribeObject(pc, 2)];
        } @catch (...) { [buf appendString:@"  (probe threw)\n"]; }

        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
        NSString *name = [NSString stringWithFormat:@"ytuhd_%@.txt", ytuhd_timestamp()];
        [buf writeToFile:[docs stringByAppendingPathComponent:name]
              atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (...) {}
}

// ---------------------------------------------------------------------------
// NSMutableURLRequest — JSON body interception (Layer 1, primary fix)
//
// Hooks setHTTPBody: because:
//   a) It fires AFTER the URL is set (so self.URL.path is available for
//      filtering) and BEFORE the request is handed to Cronet.
//   b) Cronet reads the request body from the NSMutableURLRequest object when
//      dataTaskWithRequest: is called — so our modification is what Cronet
//      actually sends.
//
// For /player, /next, and /browse paths:
//   1. Deserializes the JSON body into a mutable NSDictionary.
//   2. Extracts and persists any visitorData present in the outgoing context
//      (it comes from YouTube's own session manager and is valid for ANDROID_VR).
//   3. Replaces context.client entirely with the ANDROID_VR client dictionary,
//      injecting the persisted visitorData.
//   4. Re-serializes and passes the modified body to the original setter.
//   5. Sets matching X-YouTube-Client-Name/Version and User-Agent headers.
//
// setValue:forHTTPHeaderField: additionally captures the OAuth Bearer token
// and rewrites X-YouTube-Client-Name/Version when YouTube sets them.
// ---------------------------------------------------------------------------

%hook NSMutableURLRequest

- (void)setHTTPBody:(NSData *)body {
    NSString *path = self.URL.path;
    if (!body.length || !YTUHDIsPlayerPath(path)) {
        %orig;
        return;
    }

    id obj = [NSJSONSerialization JSONObjectWithData:body
                                            options:NSJSONReadingMutableContainers
                                              error:nil];
    if (![obj isKindOfClass:[NSMutableDictionary class]]) {
        %orig;
        return;
    }

    NSMutableDictionary *root = (NSMutableDictionary *)obj;

    // Extract visitorData from the outgoing context before we overwrite it.
    // YouTube's session manager populates this; it remains valid server-side
    // even when we change the client type.
    NSString *extractedVD = nil;
    id existingCtx = root[@"context"];
    if ([existingCtx isKindOfClass:[NSDictionary class]]) {
        id existingClient = [(NSDictionary *)existingCtx objectForKey:@"client"];
        if ([existingClient isKindOfClass:[NSDictionary class]])
            extractedVD = existingClient[@"visitorData"];
    }
    if (extractedVD.length) YTUHDSetVisitorData(extractedVD);

    // Build or update the context dict with our ANDROID_VR client.
    NSMutableDictionary *ctx;
    if ([existingCtx isKindOfClass:[NSMutableDictionary class]])
        ctx = (NSMutableDictionary *)existingCtx;
    else
        ctx = [NSMutableDictionary dictionary];

    ctx[@"client"] = YTUHDClientContext(extractedVD);
    root[@"context"] = ctx;

    NSData *newBody = [NSJSONSerialization dataWithJSONObject:root options:0 error:nil];
    if (!newBody) { %orig; return; }

    %orig(newBody);

    // Set matching identity headers.  Using the internal setter avoids
    // re-entering our hook for these specific key names.
    [self setValue:@"28"        forHTTPHeaderField:@"X-Youtube-Client-Name"];
    [self setValue:@"1.65.10"   forHTTPHeaderField:@"X-Youtube-Client-Version"];
    [self setValue:@"com.google.android.apps.youtube.vr.oculus/1.65.10 (Linux; U; Android 12L; eureka-user Build/SQ3A.220605.009.A1) gzip"
          forHTTPHeaderField:@"User-Agent"];
    [self setValue:[NSString stringWithFormat:@"%lu", (unsigned long)newBody.length]
          forHTTPHeaderField:@"Content-Length"];
}

- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    // Capture OAuth token for PO token substitution.
    if ([field caseInsensitiveCompare:@"Authorization"] == NSOrderedSame
        && [value hasPrefix:@"Bearer "]) {
        YTUHDSetOAuthToken([value substringFromIndex:7]);
    }

    // Override client name/version headers on InnerTube paths.
    if (YTUHDIsPlayerPath(self.URL.path)) {
        if ([field caseInsensitiveCompare:@"X-YouTube-Client-Name"] == NSOrderedSame) {
            %orig(@"28", field);
            return;
        }
        if ([field caseInsensitiveCompare:@"X-YouTube-Client-Version"] == NSOrderedSame) {
            %orig(@"1.65.10", field);
            return;
        }
    }

    %orig;
}

%end

// ---------------------------------------------------------------------------
// YTUHDPlayerClientProtocol — /player body rewrite for NSURLSession paths
//
// Belt-and-suspenders for any /player POST that goes through NSURLSession
// rather than Cronet.  The setHTTPBody: hook above handles Cronet.  Both can
// coexist: if setHTTPBody: already rewrote the body to ANDROID_VR, the
// clientName check below finds "ANDROID_VR" (not "IOS") and passes through.
// ---------------------------------------------------------------------------

static NSURLSession *YTUHDPlayerSession(void) {
    static NSURLSession *session;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        session = [NSURLSession sessionWithConfiguration:
            [NSURLSessionConfiguration defaultSessionConfiguration]];
    });
    return session;
}

@interface YTUHDPlayerClientProtocol : NSURLProtocol
@end

@implementation YTUHDPlayerClientProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"YTUHDHandled" inRequest:request])
        return NO;
    if (![request.HTTPMethod isEqualToString:@"POST"])
        return NO;
    if (![request.URL.path hasSuffix:@"/youtubei/v1/player"])
        return NO;
    NSString *host = request.URL.host ?: @"";
    return [host hasSuffix:@"youtube.com"] || [host hasSuffix:@"googleapis.com"];
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [super requestIsCacheEquivalent:a toRequest:b];
}

- (void)startLoading {
    NSData *body = self.request.HTTPBody;
    if (!body.length) {
        NSInputStream *stream = self.request.HTTPBodyStream;
        if (stream) {
            [stream open];
            NSMutableData *buf = [NSMutableData dataWithCapacity:8192];
            uint8_t chunk[4096];
            NSInteger n;
            while ((n = [stream read:chunk maxLength:sizeof(chunk)]) > 0)
                [buf appendBytes:chunk length:(NSUInteger)n];
            [stream close];
            body = buf.length ? buf : nil;
        }
    }

    NSMutableURLRequest *fwd = [self.request mutableCopy];
    fwd.HTTPBodyStream = nil;
    [NSURLProtocol setProperty:@YES forKey:@"YTUHDHandled" inRequest:fwd];

    BOOL modified = NO;
    if (body.length) {
        id obj = [NSJSONSerialization JSONObjectWithData:body
                                                options:NSJSONReadingMutableContainers
                                                  error:nil];
        if ([obj isKindOfClass:[NSMutableDictionary class]]) {
            NSMutableDictionary *root = obj;
            id ctx = root[@"context"];
            NSMutableDictionary *c =
                [ctx isKindOfClass:[NSMutableDictionary class]]
                    ? [(NSMutableDictionary *)ctx objectForKey:@"client"] : nil;
            // Only rewrite if still IOS — setHTTPBody: may have already done it.
            if ([c isKindOfClass:[NSMutableDictionary class]] &&
                [c[@"clientName"] isEqualToString:@"IOS"]) {
                NSString *vd = c[@"visitorData"];
                if (vd.length) YTUHDSetVisitorData(vd);
                [(NSMutableDictionary *)ctx setObject:YTUHDClientContext(vd) forKey:@"client"];
                NSData *newBody = [NSJSONSerialization dataWithJSONObject:root options:0 error:nil];
                if (newBody) {
                    fwd.HTTPBody = newBody;
                    [fwd setValue:[NSString stringWithFormat:@"%lu",
                                   (unsigned long)newBody.length]
                 forHTTPHeaderField:@"Content-Length"];
                    [fwd setValue:@"28"      forHTTPHeaderField:@"X-Youtube-Client-Name"];
                    [fwd setValue:@"1.65.10" forHTTPHeaderField:@"X-Youtube-Client-Version"];
                    modified = YES;
                }
            }
        }
        if (!modified) fwd.HTTPBody = body;
    }

    @try {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
        [[NSString stringWithFormat:@"ytuhd_player %@\nurl=%@\nmodified=%@\nbody_len=%lu\n",
            [NSDate date], self.request.URL,
            modified ? @"YES (IOS→ANDROID_VR)" : @"NO",
            (unsigned long)body.length]
         writeToFile:[docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"ytuhd_player_%@.txt", ytuhd_timestamp()]]
          atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (...) {}

    __weak YTUHDPlayerClientProtocol *weakSelf = self;
    [[YTUHDPlayerSession() dataTaskWithRequest:fwd
                             completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        YTUHDPlayerClientProtocol *s = weakSelf;
        if (!s) return;
        if (err) { [s.client URLProtocol:s didFailWithError:err]; return; }
        [s.client URLProtocol:s didReceiveResponse:resp
             cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        if (data.length) [s.client URLProtocol:s didLoadData:data];
        [s.client URLProtocolDidFinishLoading:s];
    }] resume];
}

- (void)stopLoading {}

@end

// ---------------------------------------------------------------------------
// Player pool hooks — disable SABR
//
// ANDROID_VR responses may include serverAbrStreamingUrl; useServerDrivenAbr=NO
// prevents HAMPlayer from initiating an OnesieRequest (which would require a
// PO token) and forces client-side DASH ABR instead.
// ---------------------------------------------------------------------------
%hook MLPlayerPoolImpl

- (id)acquirePlayerForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig stickySettings:(MLPlayerStickySettings *)stickySettings latencyLogger:(id)latencyLogger reloadContext:(id)reloadContext mediaPlayerResources:(id)mediaPlayerResources recompositeProvider:(id)recompositeProvider {
    YTUHDDump(video, playerConfig);
    @try {
        id pc  = [playerConfig valueForKey:@"playerConfig"];
        id mcc = [pc respondsToSelector:@selector(mediaCommonConfig)]
                     ? [pc mediaCommonConfig]
                     : [pc valueForKey:@"mediaCommonConfig"];
        if ([mcc respondsToSelector:@selector(setUseServerDrivenAbr:)])
            [mcc setUseServerDrivenAbr:NO];
    } @catch (...) {}
    return %orig;
}

- (id)playerViewForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig mediaPlayerResources:(id)mediaPlayerResources {
    return %orig;
}

- (BOOL)canQueuePlayerPlayVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig reloadContext:(id)reloadContext error:(NSError **)error {
    return NO;
}

- (BOOL)canUsePlayerView:(id)playerView forPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    return %orig;
}

%end

%hook MLPlayerPool

- (id)acquirePlayerForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig stickySettings:(MLPlayerStickySettings *)stickySettings latencyLogger:(id)latencyLogger reloadContext:(id)reloadContext mediaPlayerResources:(id)mediaPlayerResources recompositeProvider:(id)recompositeProvider {
    YTUHDDump(video, playerConfig);
    @try {
        id pc  = [playerConfig valueForKey:@"playerConfig"];
        id mcc = [pc respondsToSelector:@selector(mediaCommonConfig)]
                     ? [pc mediaCommonConfig]
                     : [pc valueForKey:@"mediaCommonConfig"];
        if ([mcc respondsToSelector:@selector(setUseServerDrivenAbr:)])
            [mcc setUseServerDrivenAbr:NO];
    } @catch (...) {}
    return %orig;
}

- (id)playerViewForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig mediaPlayerResources:(id)mediaPlayerResources {
    return %orig;
}

- (BOOL)canUsePlayerView:(id)playerView forVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    return %orig;
}

- (BOOL)canQueuePlayerPlayVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig reloadContext:(id)reloadContext error:(NSError **)error {
    return NO;
}

%end

%hook YTIMediaCommonConfig
- (BOOL)useServerDrivenAbr { return NO; }
%end

// ---------------------------------------------------------------------------
// WebM/AV1 format filter — belt-and-suspenders
// ---------------------------------------------------------------------------
static NSArray *dropWebM(NSArray *formats) {
    if (!formats.count) return formats;
    return [formats filteredArrayUsingPredicate:
        [NSPredicate predicateWithBlock:
            ^BOOL(MLFormat *fmt, NSDictionary *__unused bindings) {
                if (![fmt isKindOfClass:%c(MLFormat)]) return YES;
                NSString *urlStr = [[fmt URL] absoluteString];
                if (!urlStr) return YES;
                if ([urlStr rangeOfString:@"mime=audio/webm"   options:NSCaseInsensitiveSearch].location != NSNotFound) return NO;
                if ([urlStr rangeOfString:@"mime=video/webm"   options:NSCaseInsensitiveSearch].location != NSNotFound) return NO;
                if ([urlStr rangeOfString:@"mime=audio%2Fwebm" options:NSCaseInsensitiveSearch].location != NSNotFound) return NO;
                if ([urlStr rangeOfString:@"mime=video%2Fwebm" options:NSCaseInsensitiveSearch].location != NSNotFound) return NO;
                for (NSString *tag in @[@"itag=394", @"itag=395", @"itag=396",
                                        @"itag=397", @"itag=398", @"itag=399"]) {
                    NSRange r = [urlStr rangeOfString:tag options:NSCaseInsensitiveSearch];
                    if (r.location == NSNotFound) continue;
                    NSUInteger end = NSMaxRange(r);
                    if (end >= urlStr.length || [urlStr characterAtIndex:end] == '&')
                        return NO;
                }
                return YES;
            }]];
}

%hook MLABRPolicy
- (void)setFormats:(NSArray *)formats { %orig(dropWebM(formats)); }
%end

%hook MLABRPolicyOld
- (void)setFormats:(NSArray *)formats { %orig(dropWebM(formats)); }
%end

%hook MLABRPolicyNew
- (void)setFormats:(NSArray *)formats { %orig(dropWebM(formats)); }
%end

%hook HAMDefaultABRPolicy
- (NSArray *)filterFormats:(NSArray *)formats { return dropWebM(%orig); }
- (id)getSelectableFormatDataAndReturnError:(NSError **)error {
    [self setValue:@(NO) forKey:@"_postponePreferredFormatFiltering"];
    return dropWebM(%orig);
}
- (void)setFormats:(NSArray *)formats {
    [self setValue:@(YES) forKey:@"_postponePreferredFormatFiltering"];
    %orig(dropWebM(formats));
}
%end

%hook MLStreamingData
- (NSArray *)adaptiveStreams { return dropWebM(%orig); }
%end

// ---------------------------------------------------------------------------
// Network intercepts (NSURLProtocol)
//
// Endpoint 1: iosantiabuse-pa.googleapis.com
//   Synthetic 200 + minimal proto body so C++ sees a successful AppAttest
//   exchange and never arms the SABR kill timer.  Rate-limited to 1 per 10 s.
//
// Endpoint 2: youtubei.googleapis.com/youtubei/v1/att/get?t=
//   Fire-and-forget proxy: forward to server (keeps ATTESTATION_PENDING),
//   return empty 200 to client (Field 27 enforcement blob never delivered).
// ---------------------------------------------------------------------------
@interface YTUHDAntiAbuseProtocol : NSURLProtocol
@end

@implementation YTUHDAntiAbuseProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"YTUHDHandled" inRequest:request])
        return NO;
    NSString *host = request.URL.host;
    if ([host hasSuffix:@"iosantiabuse-pa.googleapis.com"])
        return YES;
    if ([host hasSuffix:@"youtubei.googleapis.com"]
        && [request.URL.path hasSuffix:@"/att/get"]
        && [request.URL.query hasPrefix:@"t="])
        return YES;
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [super requestIsCacheEquivalent:a toRequest:b];
}

- (void)startLoading {
    if ([self.request.URL.host hasSuffix:@"iosantiabuse-pa.googleapis.com"]) {
        static os_unfair_lock aaLock = OS_UNFAIR_LOCK_INIT;
        static CFAbsoluteTime aaNextAllowed = 0;
        os_unfair_lock_lock(&aaLock);
        CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
        BOOL allowed = (now >= aaNextAllowed);
        if (allowed) aaNextAllowed = now + 10.0;
        os_unfair_lock_unlock(&aaLock);

        if (allowed) {
            static const uint8_t kBody[] = { 0x0a, 0x08, 0, 0, 0, 0, 0, 0, 0, 0 };
            NSHTTPURLResponse *resp = [[NSHTTPURLResponse alloc]
                initWithURL:self.request.URL statusCode:200 HTTPVersion:@"HTTP/2.0"
               headerFields:@{@"Content-Type": @"application/x-protobuf",
                              @"Cache-Control": @"no-store"}];
            [self.client URLProtocol:self didReceiveResponse:resp
                  cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:[NSData dataWithBytes:kBody length:sizeof(kBody)]];
            [self.client URLProtocolDidFinishLoading:self];
        } else {
            NSHTTPURLResponse *resp = [[NSHTTPURLResponse alloc]
                initWithURL:self.request.URL statusCode:429 HTTPVersion:@"HTTP/2.0"
               headerFields:@{@"Content-Type": @"application/x-protobuf",
                              @"Retry-After":  @"10",
                              @"Cache-Control": @"no-store"}];
            [self.client URLProtocol:self didReceiveResponse:resp
                  cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:[NSData data]];
            [self.client URLProtocolDidFinishLoading:self];
        }
        return;
    }

    // att/get?t= fire-and-forget
    static NSURLSession *sideChannel;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sideChannel = [NSURLSession sessionWithConfiguration:
            [NSURLSessionConfiguration defaultSessionConfiguration]];
    });
    NSMutableURLRequest *realReq = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"YTUHDHandled" inRequest:realReq];
    [[sideChannel dataTaskWithRequest:realReq
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {}] resume];

    NSHTTPURLResponse *resp = [[NSHTTPURLResponse alloc]
        initWithURL:self.request.URL statusCode:200 HTTPVersion:@"HTTP/2.0"
       headerFields:@{@"Content-Type": @"application/x-protobuf",
                      @"Cache-Control": @"no-store"}];
    [self.client URLProtocol:self didReceiveResponse:resp
          cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:[NSData data]];
    [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {}

@end

%hook NSURLSessionConfiguration
- (NSArray *)protocolClasses {
    NSMutableArray *classes = [[NSMutableArray alloc] initWithArray:(%orig ?: @[])];
    Class antiAbuse    = [YTUHDAntiAbuseProtocol    class];
    Class playerClient = [YTUHDPlayerClientProtocol class];
    if (![classes containsObject:playerClient]) [classes insertObject:playerClient atIndex:0];
    if (![classes containsObject:antiAbuse])    [classes insertObject:antiAbuse    atIndex:0];
    return classes;
}
%end

// ---------------------------------------------------------------------------
// PO Token bypass
// ---------------------------------------------------------------------------
%hook YTHotConfig
- (BOOL)iosClientGlobalConfigDisableIosPoTokens { return YES; }
- (BOOL)iosPlayerClientSharedConfigEnablePoTokenManagerInitializationOnStartup { return NO; }
- (BOOL)iosPlayerClientSharedConfigDelayPoTokenMinterInitialization { return YES; }
- (BOOL)iosPlayerClientSharedConfigEnablePoTokenManagerMedia { return NO; }
- (BOOL)iosPlayerClientSharedConfigEnablePoTokenManagerInjection { return NO; }
- (BOOL)iosPlayerClientSharedConfigIosSpsEnablePoTokenCabr { return NO; }
- (BOOL)iosPlayerClientSharedConfigShouldReuseIosguardChallengeForAttestation { return YES; }
- (BOOL)iosPlayerClientSharedConfigRequestIosguardDataAfterPlaybackStarts { return NO; }
%end

%hook iOSGuardManager
- (BOOL)isIosguardAttestationEnabled { return NO; }
%end

%hook YTIOSGuardSnapshotControllerImpl
- (void)handleAttestationChallengeResponse:(id)response
                                     error:(NSError *)error
                                   videoID:(NSString *)videoID
                                identityID:(NSString *)identityID
                         completionHandler:(id)completionHandler {
    if (completionHandler)
        ((void (^)(id, NSError *))completionHandler)(nil, nil);
}
%end

// IGDPOTokenMinter: return the stored OAuth Bearer token as the PO token.
// The token value isn't validated structurally by GVS for ANDROID_VR, but
// having a non-empty token prevents the "no token available" grace timer from
// firing if ANDROID_VR ever triggers a SABR session internally.
%hook IGDPOTokenMinter
- (void)mintPOTokenImmediately:(id)completionHandler {
    if (completionHandler)
        ((void (^)(NSData *, NSError *))completionHandler)(YTUHDGetOAuthTokenData(), nil);
}
- (void)mintPOTokenAfterUpdate:(id)update completionQueue:(id)queue completionHandler:(id)completionHandler {
    if (completionHandler)
        ((void (^)(NSData *, NSError *))completionHandler)(YTUHDGetOAuthTokenData(), nil);
}
- (void)mintPoTokenAfterUpdate:(id)update callOnQueue:(id)queue completionHandler:(id)completionHandler {
    if (completionHandler)
        ((void (^)(NSData *, NSError *))completionHandler)(YTUHDGetOAuthTokenData(), nil);
}
- (void)mintUninitializedPoToken:(id)token initializationCalled:(BOOL)initializationCalled {}
%end

// ---------------------------------------------------------------------------
// Error logging
// ---------------------------------------------------------------------------
%hook YTMainAppVideoPlayerOverlayViewController
- (void)handleError:(NSError *)error {
    if (FixPlayback()) {
        @try {
            NSString *docs = NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES)[0];
            [[NSString stringWithFormat:@"ytuhd_error %@\ndomain=%@  code=%ld\n%@\n",
                [NSDate date], error.domain, (long)error.code, error.userInfo ?: @{}]
             writeToFile:[docs stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"ytuhd_error_%@.txt", ytuhd_timestamp()]]
              atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } @catch (...) {}
    }
    %orig;
}
%end

%ctor {
    if (!FixPlayback()) return;
    %init;
    [NSURLProtocol registerClass:[YTUHDPlayerClientProtocol class]];
    [NSURLProtocol registerClass:[YTUHDAntiAbuseProtocol class]];

    // Runtime sweep (Layer 3): replace YTIClientInfo.clientName/clientVersion
    // on all YTI-prefixed proto classes so that any internal code reading the
    // proto directly sees ANDROID_VR (28), not IOS (5).
    SEL hasPoTokenSel        = @selector(hasPoToken);
    SEL isIosguardEnabledSel = @selector(isIosguardAttestationEnabled);
    SEL clientNameSel        = @selector(clientName);
    SEL clientVersionSel     = @selector(clientVersion);

    IMP yesIMP = imp_implementationWithBlock(^BOOL(__unused id _self) { return YES; });
    IMP noIMP  = imp_implementationWithBlock(^BOOL(__unused id _self) { return NO;  });
    IMP androidVRNameIMP = imp_implementationWithBlock(^int32_t(__unused id _self) { return 28; });
    IMP androidVRVerIMP  = imp_implementationWithBlock(^NSString *(__unused id _self) { return @"1.65.10"; });

    void (^sweep)(void) = ^{
        unsigned int classCount = 0;
        Class *classes = objc_copyClassList(&classCount);
        for (unsigned int i = 0; i < classCount; i++) {
            Class cls = classes[i];
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(cls, &methodCount);
            if (!methods) continue;
            for (unsigned int j = 0; j < methodCount; j++) {
                SEL sel = method_getName(methods[j]);
                if (sel == hasPoTokenSel)
                    class_replaceMethod(cls, hasPoTokenSel, yesIMP, "B@:");
                else if (sel == isIosguardEnabledSel)
                    class_replaceMethod(cls, isIosguardEnabledSel, noIMP, "B@:");
                else if (sel == clientNameSel) {
                    const char *ret = method_copyReturnType(methods[j]);
                    BOOL isInt = ret && (ret[0] == 'i' || ret[0] == 'I');
                    if (ret) free((void *)ret);
                    if (!isInt) continue;
                    if (![NSStringFromClass(cls) hasPrefix:@"YTI"]) continue;
                    class_replaceMethod(cls, clientNameSel, androidVRNameIMP,
                                        method_getTypeEncoding(methods[j]));
                    Method vm = class_getInstanceMethod(cls, clientVersionSel);
                    if (vm) {
                        const char *vret = method_copyReturnType(vm);
                        BOOL vIsStr = vret && vret[0] == '@';
                        if (vret) free((void *)vret);
                        if (vIsStr)
                            class_replaceMethod(cls, clientVersionSel, androidVRVerIMP,
                                                method_getTypeEncoding(vm));
                    }
                }
            }
            free(methods);
        }
        free(classes);
    };

    sweep();
    dispatch_async(dispatch_get_main_queue(), sweep);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), sweep);

    // Diagnostic scan at t+3s — writes ytuhd_innertubeclass.txt to Documents.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        NSMutableString *log = [NSMutableString stringWithFormat:
            @"clientName / clientVersion scan  %@\n\n", [NSDate date]];
        SEL targets[] = {
            @selector(clientVersion),
            @selector(clientName),
            @selector(clientNameValue),
        };
        const NSUInteger targetCount = sizeof(targets) / sizeof(targets[0]);
        unsigned int classCount = 0;
        Class *classes = objc_copyClassList(&classCount);
        for (NSUInteger t = 0; t < targetCount; t++) {
            NSMutableString *hits = [NSMutableString string];
            NSUInteger n = 0;
            for (unsigned int i = 0; i < classCount; i++) {
                Method m = class_getInstanceMethod(classes[i], targets[t]);
                if (!m) continue;
                const char *ret = method_copyReturnType(m);
                [hits appendFormat:@"    %-60@  retType=%-4s  IMP=%p\n",
                    NSStringFromClass(classes[i]), ret ?: "?",
                    (void *)method_getImplementation(m)];
                if (ret) free((void *)ret);
                n++;
            }
            [log appendFormat:@"[%@]  %lu class(es)\n",
                NSStringFromSelector(targets[t]), (unsigned long)n];
            if (n) [log appendString:hits];
            [log appendString:@"\n"];
        }
        free(classes);
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES)[0];
        [log writeToFile:[docs stringByAppendingPathComponent:@"ytuhd_innertubeclass.txt"]
              atomically:YES encoding:NSUTF8StringEncoding error:nil];
    });
}
