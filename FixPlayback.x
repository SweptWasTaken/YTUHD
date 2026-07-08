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
//   Protection Context) signed with the empty PO token at player-request time:
//     itag=251 (WebM/Opus audio)  — error log build 1
//     itag=398 (AV1/MP4 video)   — error log build 2
//     itag=298 (H.264/MP4 video) — error log build 3
//
// Fix: spoof the InnerTube client to ANDROID_VR (Oculus Quest, client ID 28).
//
//   ANDROID_VR returns standard DASH adaptive streams that are currently exempt
//   from PO token enforcement on GVS — no spc= validation occurs.  HAMPlayer
//   handles DASH natively so renderViewType stays at the server default; no
//   AVPlayer or HLS injection is needed.
//
//   The client swap is applied at two layers:
//     1. ObjC runtime sweep — replaces YTIClientInfo.clientName (int32 proto
//        getter, IOS=5 → ANDROID_VR=28) on every class that implements it.
//        This travels with ALL requests including Cronet-backed ones.
//     2. YTUHDPlayerClientProtocol (NSURLProtocol) — rewrites /player POST
//        body for any request that goes through NSURLSession (belt-and-suspenders;
//        Cronet-backed calls are already handled by the sweep above).
//
//   SABR is disabled (useServerDrivenAbr=NO) to prevent OnesieRequests entirely,
//   since ANDROID_VR responses may still include serverAbrStreamingUrl.
//
//   Anti-abuse and att/get intercepts remain active to prevent the AppAttest
//   400 from reaching C++ and arming the SABR kill timer.

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
// Runtime diagnostic dump
//
// Written to Documents/ytuhd_<timestamp>.txt on every acquirePlayerForVideo
// call.  Open in Files app or any file manager to inspect the player config.
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
// YTUHDPlayerClientProtocol — swap IOS → ANDROID_VR on /youtubei/v1/player
//
// Belt-and-suspenders for /player POSTs that go through NSURLSession (not
// Cronet).  The ObjC runtime sweep in %ctor handles Cronet-backed calls by
// replacing YTIClientInfo.clientName at the proto layer; this protocol catches
// any remaining NSURLSession code paths.
//
// If the request body contains clientName="IOS" the body is rewritten to
// ANDROID_VR with the correct version and device fields.  Requests whose body
// is not IOS JSON are forwarded unmodified.
//
// A ytuhd_player_<ts>.txt file is written to Documents on every intercept.
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
            NSMutableDictionary *c =
                [root[@"context"] isKindOfClass:[NSMutableDictionary class]]
                    ? [(NSMutableDictionary *)root[@"context"] objectForKey:@"client"]
                    : nil;
            if ([c isKindOfClass:[NSMutableDictionary class]] &&
                [c[@"clientName"] isEqualToString:@"IOS"]) {
                c[@"clientName"]         = @"ANDROID_VR";
                c[@"clientVersion"]      = @"1.65.10";
                c[@"deviceMake"]         = @"Oculus";
                c[@"deviceModel"]        = @"Quest 3";
                c[@"androidSdkVersion"]  = @32;
                c[@"osName"]             = @"Android";
                c[@"osVersion"]          = @"12L";
                [c removeObjectForKey:@"userAgent"];
                NSData *newBody = [NSJSONSerialization dataWithJSONObject:root options:0 error:nil];
                if (newBody) {
                    fwd.HTTPBody = newBody;
                    [fwd setValue:[NSString stringWithFormat:@"%lu",
                                   (unsigned long)newBody.length]
                 forHTTPHeaderField:@"Content-Length"];
                    [fwd setValue:@"28"        forHTTPHeaderField:@"X-Youtube-Client-Name"];
                    [fwd setValue:@"1.65.10"   forHTTPHeaderField:@"X-Youtube-Client-Version"];
                    [fwd setValue:@"com.google.android.apps.youtube.vr.oculus/1.65.10 (Linux; U; Android 12L; eureka-user Build/SQ3A.220605.009.A1) gzip"
                 forHTTPHeaderField:@"User-Agent"];
                    modified = YES;
                }
            }
        }
        if (!modified) fwd.HTTPBody = body;
    }

    @try {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
        NSString *log = [NSString stringWithFormat:
            @"ytuhd_player %@\nurl=%@\nmodified=%@\nbody_len=%lu\n",
            [NSDate date], self.request.URL,
            modified ? @"YES (IOS→ANDROID_VR)" : @"NO",
            (unsigned long)body.length];
        [log writeToFile:[docs stringByAppendingPathComponent:
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
// Player pool hooks
//
// SABR is disabled via useServerDrivenAbr=NO to prevent OnesieRequests, which
// require a PO token.  ANDROID_VR responses may still include
// serverAbrStreamingUrl; this ensures HAMPlayer uses client-side DASH ABR
// instead, which skips the OnesieRequest entirely.
//
// renderViewType is left at the server-sent default — ANDROID_VR streams are
// standard DASH and HAMPlayer handles them natively without AVPlayer.
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

// ---------------------------------------------------------------------------
// SABR bypass
//
// Returning NO from useServerDrivenAbr causes HAMPlayer to skip the
// OnesieRequest (initplayback) entirely, so it never presents a PO token to
// GVS.  HAMPlayer falls back to client-side DASH ABR using the adaptiveStreams
// list from the /player response.
// ---------------------------------------------------------------------------
%hook YTIMediaCommonConfig
- (BOOL)useServerDrivenAbr { return NO; }
%end

// ---------------------------------------------------------------------------
// WebM/AV1 format filter
//
// Strips WebM (VP9 video + Opus audio) and AV1-in-MP4 (itag 394-399) from
// the adaptive streams list.  These codecs are not supported in sideloaded
// builds and may carry additional GVS enforcement.  Belt-and-suspenders since
// ANDROID_VR responses primarily serve H.264/AAC.
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
//   LiveContainer2's wrong Team ID causes every AppAttest exchange to return
//   400.  C++ caches that failure and arms a SABR kill timer on the next
//   session.  We return a synthetic 200 + minimal proto body so C++ sees a
//   successful exchange and never caches a failure state.
//   Rate-limited to one synthetic 200 per 10 s to avoid C++ retry loops.
//
// Endpoint 2: youtubei.googleapis.com/youtubei/v1/att/get?t=
//   The ?t= parameter is the CPN (Client Playback Nonce).  YouTube uses this
//   as an attestation heartbeat; Field 27 in the response is an enforcement
//   blob that arms a kill timer 69-73 ms after arrival.  We proxy the request
//   to the real server (keeping the server heartbeat alive so it stays in
//   ATTESTATION_PENDING and continues pushing media) while returning an empty
//   200 to the client — Field 27 is never delivered, kill timer never armed.
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
        static const CFTimeInterval kAAMinInterval = 10.0;

        os_unfair_lock_lock(&aaLock);
        CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
        BOOL allowed = (now >= aaNextAllowed);
        if (allowed) aaNextAllowed = now + kAAMinInterval;
        os_unfair_lock_unlock(&aaLock);

        if (allowed) {
            static const uint8_t kAntiAbuseBody[] = { 0x0a, 0x08, 0, 0, 0, 0, 0, 0, 0, 0 };
            NSData *body = [NSData dataWithBytes:kAntiAbuseBody length:sizeof(kAntiAbuseBody)];
            NSHTTPURLResponse *resp = [[NSHTTPURLResponse alloc]
                initWithURL:self.request.URL statusCode:200 HTTPVersion:@"HTTP/2.0"
               headerFields:@{@"Content-Type": @"application/x-protobuf",
                              @"Cache-Control": @"no-store"}];
            [self.client URLProtocol:self didReceiveResponse:resp
                  cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:body];
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

    // att/get?t= — fire-and-forget proxy
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
//
// Belt-and-suspenders hooks for code paths that bypass the URL loading system.
// The primary fix is the runtime sweep in %ctor + the anti-abuse protocol
// above.  These hooks prevent the token manager from spinning up.
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

%hook IGDPOTokenMinter
- (void)mintPOTokenImmediately:(id)completionHandler {
    if (completionHandler)
        ((void (^)(NSData *, NSError *))completionHandler)([NSData data], nil);
}
- (void)mintPOTokenAfterUpdate:(id)update completionQueue:(id)queue completionHandler:(id)completionHandler {
    if (completionHandler)
        ((void (^)(NSData *, NSError *))completionHandler)([NSData data], nil);
}
- (void)mintPoTokenAfterUpdate:(id)update callOnQueue:(id)queue completionHandler:(id)completionHandler {
    if (completionHandler)
        ((void (^)(NSData *, NSError *))completionHandler)([NSData data], nil);
}
- (void)mintUninitializedPoToken:(id)token initializationCalled:(BOOL)initializationCalled {}
%end

// ---------------------------------------------------------------------------
// Error logging
//
// Writes every player error to Documents/ytuhd_error_<ts>.txt so we can see
// what the player framework reports without needing a debugger.
// ---------------------------------------------------------------------------
%hook YTMainAppVideoPlayerOverlayViewController
- (void)handleError:(NSError *)error {
    if (FixPlayback()) {
        @try {
            NSString *docs = NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES)[0];
            NSString *msg = [NSString stringWithFormat:
                @"ytuhd_error %@\ndomain=%@  code=%ld\n%@\n",
                [NSDate date], error.domain, (long)error.code, error.userInfo ?: @{}];
            [msg writeToFile:[docs stringByAppendingPathComponent:
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

    // Runtime sweep: replace YTIClientInfo.clientName and related selectors
    // on every class that implements them.
    //
    // Targets:
    //   hasPoToken              → YES  (BOOL)
    //   isIosguardAttestationEnabled → NO  (BOOL)
    //   clientName (int, YTI*) → 28   (ANDROID_VR; IOS=5, TVHTML5=7)
    //   clientVersion (str, YTI*) → "1.65.10"
    //
    // The sweep runs synchronously at dyld-init time (catches classes already
    // registered), then twice on the main queue (catches GPBMessage subclasses
    // registered lazily after UIApplicationMain).

    SEL hasPoTokenSel        = @selector(hasPoToken);
    SEL isIosguardEnabledSel = @selector(isIosguardAttestationEnabled);
    SEL clientNameSel        = @selector(clientName);
    SEL clientVersionSel     = @selector(clientVersion);

    IMP yesIMP = imp_implementationWithBlock(^BOOL(__unused id _self) { return YES; });
    IMP noIMP  = imp_implementationWithBlock(^BOOL(__unused id _self) { return NO;  });

    // ANDROID_VR = client enum 28 (confirmed from InnerTube proto; IOS=5, TVHTML5=7)
    IMP androidVRClientNameIMP = imp_implementationWithBlock(
        ^int32_t(__unused id _self) { return 28; });
    IMP androidVRVersionIMP = imp_implementationWithBlock(
        ^NSString *(__unused id _self) { return @"1.65.10"; });

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
                    // 141 iOS system classes (Photos, AVCapture, HomeKit…) also
                    // have clientName — filter to YTI-prefixed classes with int
                    // return type (YouTube InnerTube proto classes only).
                    const char *ret = method_copyReturnType(methods[j]);
                    BOOL isInt = ret && (ret[0] == 'i' || ret[0] == 'I');
                    if (ret) free((void *)ret);
                    if (!isInt) continue;
                    if (![NSStringFromClass(cls) hasPrefix:@"YTI"]) continue;
                    class_replaceMethod(cls, clientNameSel, androidVRClientNameIMP,
                                        method_getTypeEncoding(methods[j]));
                    Method vm = class_getInstanceMethod(cls, clientVersionSel);
                    if (vm) {
                        const char *vret = method_copyReturnType(vm);
                        BOOL vIsStr = vret && vret[0] == '@';
                        if (vret) free((void *)vret);
                        if (vIsStr)
                            class_replaceMethod(cls, clientVersionSel, androidVRVersionIMP,
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

    // Diagnostic: scan at t+3s and write ytuhd_innertubeclass.txt to Documents.
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
