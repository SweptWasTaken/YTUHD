// Adapted from YouPiP by PoomSmart
// Updated for YouTube 21.20.4 - removed dead hooks, fixed signatures
//
// Root cause summary (confirmed via HAR + binary analysis + proto RE):
//
// YouTube on iOS uses SABR (Server-Driven ABR) via the HAMPlayer SDK.
// SABR requires a PO (Proof of Origin) token minted via Apple AppAttest.
// Inside LiveContainer2 the AppAttest payload carries LiveContainer's
// re-signing Team ID (LSMHR68PG6), so every exchange with
// iosantiabuse-pa.googleapis.com returns 400 — no valid PO token is ever
// obtained.  GVS responds to OnesieRequests that have a missing/empty
// poToken with STREAM_PROTECTION_STATUS=3 (ATTESTATION_REQUIRED), which
// the client's C++ SABR session manager processes and converts to
// Code=14 "Something went wrong".
//
// Key insight: this Code=14 kill is delivered via the encrypted UMP SABR
// stream — it cannot be intercepted by NSURLProtocol or any ObjC hook.
// Client-side fixes (disabling PO token manager, faking iosantiabuse
// responses, fire-and-forget att/get proxying) address symptoms but not
// the kill path itself.
//
// The correct fix is to disable SABR entirely via useServerDrivenAbr=NO
// on YTIMediaCommonConfig.  HAMPlayer then falls back to client-side ABR
// using the hlsManifestUrl from the /youtubei/v1/player response.  HLS
// segment requests to GVS currently do NOT require PO tokens, so playback
// proceeds without any attestation machinery.
//
// Stack after fix: AVPlayer (renderViewType=2) + HLS manifest → GVS HLS
// segments → no SABR → no STREAM_PROTECTION_STATUS → no Code=14.

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



__attribute__((unused))
static void forceRenderViewTypeBase(YTIHamplayerConfig *hamplayerConfig) {
    if (!hamplayerConfig) return;
    hamplayerConfig.renderViewType = 2;
    // Zero out VP9 and AV1 max resolution in the HAMPlayer stream filter.
    // This tells HAMPlayer's format selector that no VP9 or AV1 stream has a
    // valid resolution, effectively disabling both codecs.  Without them,
    // HAMPlayer falls back to H.264 (video) and AAC (audio) — native iOS
    // hardware codecs that do not carry the WebM/Opus PO token enforcement.
    YTIHamplayerStreamFilter *filter = hamplayerConfig.streamFilter;
    if (filter) {
        filter.vp9.maxArea = 0;
        filter.vp9.maxFps  = 0;
        filter.av1.maxArea = 0;
        filter.av1.maxFps  = 0;
    }
}

__attribute__((unused))
static void forceRenderViewTypeHot(YTIHamplayerHotConfig *hamplayerHotConfig) {
    if (!hamplayerHotConfig) return;
    hamplayerHotConfig.renderViewType = 2;
}

__attribute__((unused))
static void forceRenderViewType(YTHotConfig *hotConfig) {
    YTIHamplayerHotConfig *hamplayerHotConfig = [hotConfig hamplayerHotConfig];
    forceRenderViewTypeHot(hamplayerHotConfig);
}

// ---------------------------------------------------------------------------
// Runtime diagnostic dump
//
// Every time makeAVPlayer() fires, YTUHDDump() serialises the full property
// graph of MLVideo and MLInnerTubePlayerConfig (3 levels deep) to a
// timestamped text file in the app's Documents folder.
//
// To read the file:
//   FLEX toolbar → filesystem icon → navigate to Documents →
//   open ytuhd_<unix-timestamp>.txt
//
// Each video-load attempt appends a new file so you can compare across tries.
// The dump is wrapped in @try so it can never crash the player.
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
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES)[0];
        NSString *name = [NSString stringWithFormat:@"ytuhd_%@.txt", ytuhd_timestamp()];
        [buf writeToFile:[docs stringByAppendingPathComponent:name]
              atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (...) { /* never crash the player */ }
}

// ---------------------------------------------------------------------------
// ytuhd_fetchHLSURL — out-of-band WEB_EMBEDDED_PLAYER player request
//
// The IOS client no longer includes hlsManifestUrl in its /youtubei/v1/player
// response for this account (confirmed: dump shows HLSMasterPlaylistURL=nil
// and c=IOS in serverABRStreamingURL even with useServerDrivenAbr=NO).
//
// WEB_EMBEDDED_PLAYER (clientId=56) always returns hlsManifestUrl (non-DRM
// HLS) and is not subject to PO token enforcement on GVS.  We make a direct
// NSURLSession request here — completely separate from the Cronet-backed
// InnerTube channel — so the client type is fully under our control.
//
// Recent YouTube server-side change: for some accounts the IOS client response
// now returns serverAbrStreamingUrl (field 15) instead of hlsManifestUrl
// (field 5).  The same shift may affect WEB_EMBEDDED_PLAYER responses for
// those accounts.  We therefore try three clients in sequence and take the
// first one that gives back a hlsManifestUrl.
//
// Clients tried (in order):
//   1. WEB_EMBEDDED_PLAYER (56) — embedded iframe player
//   2. MWEB (2)                  — mobile web, separate server-side ruleset
//   3. TVHTML5 (7)               — TV client, always returns HLS (no SABR path)
//
// All network I/O runs on a background GCD queue so the calling thread
// (which may be the main thread) is never blocked for more than 12 s total.
//
// A ytuhd_fetch_<ts>.txt file is written to Documents after every attempt
// so you can open it in FLEX → Files and see exactly what each client
// returned (HTTP status, hlsManifestUrl, serverAbrStreamingUrl presence).
// ---------------------------------------------------------------------------
static NSString *ytuhd_fetchHLSURL(NSString *videoID) {
    if (!videoID.length) return nil;

    // Each entry: clientName, clientVersion, X-Youtube-Client-Name value,
    //             Origin header, Referer header.
    NSArray *clients = @[
        @{ @"name": @"WEB_EMBEDDED_PLAYER", @"version": @"2.20231219.04.00", @"id": @"56",
           @"origin": @"https://www.youtube.com",
           @"referer": @"https://www.youtube.com/embed/" },
        @{ @"name": @"MWEB",                @"version": @"2.20231219.07.00", @"id": @"2",
           @"origin": @"https://m.youtube.com",
           @"referer": @"https://m.youtube.com/" },
        @{ @"name": @"TVHTML5",             @"version": @"7.20240918.01.00", @"id": @"7",
           @"origin": @"https://www.youtube.com",
           @"referer": @"https://www.youtube.com/" },
    ];

    NSURL *url = [NSURL URLWithString:
        @"https://www.youtube.com/youtubei/v1/player"
         "?key=AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8"
         "&prettyPrint=false"];

    __block NSString *hlsURL = nil;
    NSMutableString *log = [NSMutableString stringWithFormat:
        @"ytuhd_fetch %@  videoID=%@\n\n", [NSDate date], videoID];

    // Run all network work on a background queue — safe even if the caller is
    // the main thread.  We wait on the outer semaphore with a hard 12 s cap.
    dispatch_semaphore_t outerSem = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{

        for (NSDictionary *client in clients) {
            if (hlsURL) break;

            NSMutableURLRequest *req =
                [NSMutableURLRequest requestWithURL:url
                                        cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                    timeoutInterval:8.0];
            req.HTTPMethod = @"POST";
            [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            [req setValue:client[@"id"]       forHTTPHeaderField:@"X-Youtube-Client-Name"];
            [req setValue:client[@"version"]  forHTTPHeaderField:@"X-Youtube-Client-Version"];
            [req setValue:client[@"origin"]   forHTTPHeaderField:@"Origin"];
            [req setValue:client[@"referer"]  forHTTPHeaderField:@"Referer"];

            NSDictionary *body = @{
                @"videoId": videoID,
                @"context": @{ @"client": @{
                    @"clientName":    client[@"name"],
                    @"clientVersion": client[@"version"],
                    @"hl":            @"en"
                }}
            };
            req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];

            __block NSInteger httpStatus = 0;
            __block NSString *candidate  = nil;
            __block BOOL hasSABR         = NO;
            dispatch_semaphore_t inner = dispatch_semaphore_create(0);

            NSURLSessionConfiguration *cfg =
                [NSURLSessionConfiguration ephemeralSessionConfiguration];
            cfg.timeoutIntervalForRequest = 8.0;
            NSURLSession *sess = [NSURLSession sessionWithConfiguration:cfg];

            [[sess dataTaskWithRequest:req
                    completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                httpStatus = [(NSHTTPURLResponse *)r statusCode];
                if (!e && d.length) {
                    id json = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
                    id sd = [json isKindOfClass:[NSDictionary class]] ? json[@"streamingData"] : nil;
                    if ([sd isKindOfClass:[NSDictionary class]]) {
                        candidate = sd[@"hlsManifestUrl"];
                        hasSABR   = (sd[@"serverAbrStreamingUrl"] != nil);
                    }
                }
                dispatch_semaphore_signal(inner);
            }] resume];

            dispatch_semaphore_wait(inner, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC));
            [sess finishTasksAndInvalidate];

            [log appendFormat:@"%@  HTTP %ld  hls=%@  sabr=%@\n",
                client[@"name"], (long)httpStatus,
                candidate ?: @"(nil)",
                hasSABR ? @"YES" : @"no"];

            if (candidate.length) hlsURL = candidate;
        }

        dispatch_semaphore_signal(outerSem);
    });

    dispatch_semaphore_wait(outerSem, dispatch_time(DISPATCH_TIME_NOW, 12 * NSEC_PER_SEC));

    [log appendFormat:@"\nresult: %@\n", hlsURL ?: @"NONE — no client returned hlsManifestUrl"];

    // Write fetch diagnostic to Documents (readable via FLEX Files browser).
    @try {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES)[0];
        NSString *name = [NSString stringWithFormat:@"ytuhd_fetch_%@.txt", ytuhd_timestamp()];
        [log writeToFile:[docs stringByAppendingPathComponent:name]
              atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (...) {}

    return hlsURL;
}

// ---------------------------------------------------------------------------
// ytuhd_injectHLSURL — write hlsManifestUrl into the live MLStreamingData
//
// MLStreamingData.HLSMasterPlaylistURL is a read-only computed property that
// reads YTIStreamingData.hlsManifestURL (a proto-generated NSString property
// with a real setter).  We walk the MLStreamingData ivar tree to find the
// inner YTIStreamingData instance and call its setter directly.
//
// Three strategies, applied in order until one succeeds:
//   1. KVC probe with known key names for the inner proto reference.
//   2. Full ivar scan (object-type ivars only, checked via type encoding).
//   3. Direct setter on MLStreamingData itself (in case it IS the proto).
// ---------------------------------------------------------------------------
static void ytuhd_injectHLSURL(MLStreamingData *sd, NSString *urlString) {
    if (!sd || !urlString.length) return;
    SEL setter = @selector(setHlsManifestURL:);

    // setHlsManifestURL: returns void so there is no actual leak, but ARC
    // can't prove that without a visible declaration.  Suppress the warning
    // for the whole injection function.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

    // Strategy 1: known ivar key names.
    for (NSString *key in @[@"_streamingData", @"_proto", @"_data",
                             @"streamingData",  @"innerStreamingData",
                             @"ytStreamingData", @"_ytStreamingData"]) {
        @try {
            id inner = [sd valueForKey:key];
            if (inner && [inner respondsToSelector:setter]) {
                [inner performSelector:setter withObject:urlString];
                goto done;
            }
        } @catch (...) {}
    }

    // Strategy 2: ivar scan — object-type ivars only.
    for (Class cls = [sd class];
         cls && cls != [NSObject class];
         cls = [cls superclass]) {
        unsigned int n = 0;
        Ivar *ivars = class_copyIvarList(cls, &n);
        if (!ivars) continue;
        for (unsigned int i = 0; i < n; i++) {
            const char *enc = ivar_getTypeEncoding(ivars[i]);
            if (!enc || enc[0] != '@') continue;
            @try {
                id val = object_getIvar(sd, ivars[i]);
                if (val && [val respondsToSelector:setter]) {
                    [val performSelector:setter withObject:urlString];
                    free(ivars);
                    goto done;
                }
            } @catch (...) {}
        }
        free(ivars);
    }

    // Strategy 3: sd itself might expose the setter.
    @try {
        if ([sd respondsToSelector:setter])
            [sd performSelector:setter withObject:urlString];
    } @catch (...) {}

done:;
#pragma clang diagnostic pop
}

// ---------------------------------------------------------------------------
// makeAVPlayer — kept for potential future use; NOT called by any hook.
//
// Out-of-band HLS fetch via ytuhd_fetchHLSURL was abandoned: all three client
// types (WEB_EMBEDDED_PLAYER, MWEB, TVHTML5) returned HTTP 200 but empty
// streamingData (no hlsManifestUrl, no serverAbrStreamingUrl).  YouTube's
// InnerTube API now requires the app's own Cronet-managed auth cookies/tokens
// for any player request to succeed; our standalone NSURLSession calls have
// no access to Cronet's cookie store and are bot-detected server-side.
//
// Current strategy: let HAMPlayer run (call %orig in acquirePlayerForVideo),
// disable SABR via useServerDrivenAbr=NO so HAMPlayer uses client-side DASH
// ABR instead.  Only H.264/AAC streams survive the dropWebM filter, so
// HAMPlayer never attempts the WebM/Opus (itag=251) segments that originally
// triggered the PO-token 403 enforcement.
// ---------------------------------------------------------------------------
__attribute__((unused))
static MLAVPlayer *makeAVPlayer(id self,
                                MLVideo *video,
                                MLInnerTubePlayerConfig *playerConfig,
                                MLPlayerStickySettings *stickySettings) {
    // Dump pre-injection state so we can inspect HLSMasterPlaylistURL before
    // and after our fetch.  A second dump is written after injection below.
    YTUHDDump(video, playerConfig);

    // If the IOS client gave us no HLS URL (typical since YouTube removed
    // hlsManifestUrl from IOS responses in favour of SABR), fetch one
    // ourselves as WEB_EMBEDDED_PLAYER, which always returns hlsManifestUrl.
    //
    // Use KVC throughout: MLVideo and MLStreamingData headers don't publicly
    // expose every method we need, and KVC avoids "no visible @interface"
    // errors while staying safe (wrapped in @try).
    MLStreamingData *sd = nil;
    @try { sd = [video valueForKey:@"streamingData"]; } @catch (...) {}
    NSURL *existingHLS = nil;
    @try { existingHLS = [sd valueForKey:@"HLSMasterPlaylistURL"]; } @catch (...) {}
    if (sd && !existingHLS) {
        NSString *videoID = nil;
        @try { videoID = [video valueForKey:@"videoID"]; } @catch (...) {}
        if (!videoID.length) @try { videoID = [video valueForKey:@"ID"]; } @catch (...) {}
        if (videoID.length) {
            NSString *hlsURL = ytuhd_fetchHLSURL(videoID);
            if (hlsURL.length) {
                ytuhd_injectHLSURL(sd, hlsURL);
                // Second dump: confirms HLSMasterPlaylistURL is now non-nil.
                YTUHDDump(video, playerConfig);
            }
        }
    }

    BOOL ext = [(MLAVPlayer *)[self valueForKey:@"_activePlayer"] externalPlaybackActive];
    MLAVPlayer *player = [[%c(MLAVPlayer) alloc]
        initWithVideo:video
         playerConfig:playerConfig
       stickySettings:stickySettings
externalPlaybackActive:ext];
    if (stickySettings) player.rate = stickySettings.rate;
    return player;
}

%hook MLPlayerPoolImpl

// Let HAMPlayer run normally.  SABR is disabled by the YTIMediaCommonConfig
// hook below; we also write useServerDrivenAbr=NO directly on the proto object
// here in case HAMPlayer's C++ layer reads it via the C++ proto API (which
// bypasses ObjC hooks).  With SABR off, HAMPlayer falls back to client-side
// DASH ABR using the adaptiveStreams list — the dropWebM/MLStreamingData hooks
// strip out every WebM/Opus format first, so HAMPlayer can only select H.264
// video and AAC audio tracks, neither of which currently triggers GVS PO-token
// enforcement for the IOS client.
- (id)acquirePlayerForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig stickySettings:(MLPlayerStickySettings *)stickySettings latencyLogger:(id)latencyLogger reloadContext:(id)reloadContext mediaPlayerResources:(id)mediaPlayerResources recompositeProvider:(id)recompositeProvider {
    YTUHDDump(video, playerConfig);
    @try {
        id mcc = [[playerConfig playerConfig] mediaCommonConfig];
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
        id mcc = [[playerConfig playerConfig] mediaCommonConfig];
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

// MLDefaultPlayerViewFactory and MLVideoDecoderFactory hooks removed.
// renderViewType forcing is no longer applied: HAMPlayer runs with the
// server-sent renderViewType (6 = SBDL_SAMPLE_BUFFER) and handles its own
// view and decoder setup.  Forcing renderViewType=2 caused the pool to
// create MLAVPlayer (standalone), which requires hlsManifestUrl — absent
// from IOS client responses since YouTube migrated to SABR.

// ---------------------------------------------------------------------------
// SABR bypass — the actual root cause of STREAM_PROTECTION_STATUS=3 Code=14
//
// SABR (Server-Driven ABR) is YouTube's server-push adaptive bitrate protocol.
// The client initiates a SABR session by sending an OnesieRequest
// (initplayback) to the GVS CDN.  The OnesieRequest's StreamerContext (field
// 10, plaintext proto) must include a valid PO (Proof of Origin) token minted
// via Apple AppAttest.  Inside LiveContainer2, AppAttest embeds LiveContainer's
// re-signing Team ID (LSMHR68PG6) instead of YouTube's, so every AppAttest
// exchange returns 400 — no valid PO token can be obtained.
//
// When GVS receives an OnesieRequest with a missing/empty poToken it sends
// STREAM_PROTECTION_STATUS=2 (ATTESTATION_PENDING) and then
// STREAM_PROTECTION_STATUS=3 (ATTESTATION_REQUIRED) once the grace period
// expires.  The client's C++ SABR session manager reads Status=3 from the UMP
// stream and fires Code=14 "Something went wrong" — this happens regardless
// of any client-side ObjC-layer fix because the enforcement message travels
// inside the encrypted SABR UMP stream where NSURLProtocol cannot reach it.
//
// Fix: returning NO from useServerDrivenAbr causes HAMPlayer to skip the
// OnesieRequest entirely and fall back to client-side DASH ABR.  The
// dropWebM/MLStreamingData hooks strip all WebM (VP9/Opus) formats from the
// adaptiveStreams list, so the only candidates are H.264 video and AAC audio.
// Those DASH segment URLs do not appear to carry the same GVS PO-token
// enforcement that triggered the original itag=251 403.
//
// The complete stack with SABR disabled:
//   HAMPlayer (SBDL renderer) + client DASH → H.264/AAC segments → no SABR
//   → no OnesieRequest → no PO token requirement → playback proceeds.
// ---------------------------------------------------------------------------
%hook YTIMediaCommonConfig
- (BOOL)useServerDrivenAbr { return NO; }
%end

// YTGLMediaPlayerViewFactory renderViewType hooks removed — no longer forcing
// renderViewType=2; HAMPlayer selects its own view type based on server config.

// ---------------------------------------------------------------------------
// WebM/Opus format filter — ABR policy level
//
// GVS 403s DASH segments that carry the `spc` (Stream Protection Context)
// parameter when no valid PO token was provided at session init.  In the
// current YouTube 21.x enforcement regime this hits WebM/VP9 video and
// WebM/Opus audio (itag=251) segments for the IOS client.  Native iOS
// codecs (H.264 video, AAC audio) currently do not trigger enforcement.
//
// The stream filter in forceRenderViewTypeBase zeroes VP9/AV1 max area,
// which prevents HAMPlayer from ever proposing those formats.  These ABR
// policy hooks are belt-and-suspenders: they run AFTER format list
// assembly and strip any remaining WebM format before the ABR algorithm
// makes a selection.  The check is purely on the URL's MIME query param —
// no enum magic required.
//
// Note: Tweak.xm's equivalent hooks are skipped when FixPlayback()=YES
// (see Tweak.xm %ctor guard), so these hooks must live here.
// ---------------------------------------------------------------------------
static NSArray *dropWebM(NSArray *formats) {
    if (!formats.count) return formats;
    return [formats filteredArrayUsingPredicate:
        [NSPredicate predicateWithBlock:
            ^BOOL(MLFormat *fmt, NSDictionary *__unused bindings) {
                if (![fmt isKindOfClass:%c(MLFormat)]) return YES;
                NSString *urlStr = [[fmt URL] absoluteString];
                if (!urlStr) return YES;
                // MIME type appears in the URL as mime=audio/webm or
                // mime=video/webm (slash is typically unencoded in query params).
                if ([urlStr rangeOfString:@"mime=audio/webm"
                                 options:NSCaseInsensitiveSearch].location != NSNotFound)
                    return NO;
                if ([urlStr rangeOfString:@"mime=video/webm"
                                 options:NSCaseInsensitiveSearch].location != NSNotFound)
                    return NO;
                // Percent-encoded variants (belt-and-suspenders).
                if ([urlStr rangeOfString:@"mime=audio%2Fwebm"
                                 options:NSCaseInsensitiveSearch].location != NSNotFound)
                    return NO;
                if ([urlStr rangeOfString:@"mime=video%2Fwebm"
                                 options:NSCaseInsensitiveSearch].location != NSNotFound)
                    return NO;
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

// ---------------------------------------------------------------------------
// MLStreamingData format filter — highest-level ObjC interception point
//
// The ABR policy hooks above (MLABRPolicy*, HAMDefaultABRPolicy) target the
// ObjC ABR objects, but in YouTube 21.x HAMPlayer's C++ ABR core reads the
// format list directly via objc_msgSend on MLStreamingData.adaptiveStreams —
// it never goes through the ObjC ABR policy objects at all.  That's why the
// dropWebM() calls in those hooks are effectively dead code.
//
// MLStreamingData.adaptiveStreams IS the authoritative format list: it returns
// NSArray<MLRemoteStream *>, where MLRemoteStream is a subclass of MLFormat.
// The existing dropWebM() predicate (which checks [[fmt URL] absoluteString]
// for "mime=audio/webm" / "mime=video/webm") works directly on MLRemoteStream
// objects because they inherit -URL from MLFormat.
//
// By filtering here we remove WebM/Opus (itag=251) and WebM/VP9 before C++
// ever sees the format list, so the ABR algorithm can only select H.264 video
// and AAC audio — formats that don't trigger GVS PO token enforcement for the
// IOS client.
// ---------------------------------------------------------------------------
%hook MLStreamingData
- (NSArray *)adaptiveStreams { return dropWebM(%orig); }
%end

// ---------------------------------------------------------------------------
// Network intercept (NSURLProtocol) — two endpoints
//
// ── Endpoint 1: iosantiabuse-pa.googleapis.com/v1/exchange ─────────────────
//
//   Root cause of the 4-second SABR kill (confirmed via HAR analysis):
//
//   LiveContainer2 re-signs YouTube with Team ID LSMHR68PG6 instead of
//   YouTube's real Team ID, so every AppAttest exchange returns 400
//   "Precondition check failed."  The C++ iosguard layer parses that 400
//   BEFORE any ObjC code runs, writing "exchange failed" to a C++ global.
//   When the next SABR session starts, it reads the cached failure and arms
//   a 4-second kill timer — bypassing the ObjC hasPoToken check entirely.
//
//   Fix: replace the 400 with a synthetic 200 + minimal proto body.
//   C++ sees a successful exchange, never writes the failure state, and no
//   kill timer is armed.  Token content is not validated server-side.
//
// ── Endpoint 2: youtubei.googleapis.com/youtubei/v1/att/get?t=<token> ──────
//
//   Root cause of the 69-73 ms SABR kill (confirmed via HAR analysis):
//
//   The ?t= parameter IS the CPN (Client Playback Nonce) for the active
//   video session.  YouTube POSTs to /att/get?t=<CPN> as an attestation
//   heartbeat.  The server response is a proto that sometimes contains
//   Field 27 — a 51-byte enforcement blob.  When Field 27 is present, the
//   YouTube player kills the SABR stream exactly 69-73 ms after the
//   response arrives (confirmed: two qoe:mta events, gaps of 69 ms and
//   73 ms, each immediately following an att/get?t= response).
//
//   CRITICAL: att/get?t= is also the server-side keep-alive.  When the
//   server receives att/get?t=<CPN> it knows the client is still trying to
//   obtain a PO token and keeps STREAM_PROTECTION_STATUS = ATTESTATION_PENDING
//   (server continues pushing media chunks).  Blocking att/get?t= entirely
//   (returning synthetic 200 without forwarding) stops the server heartbeat,
//   causing the server to transition to ATTESTATION_REQUIRED sooner — the
//   video buffer shrinks from ~60-79 s to under 2 s (confirmed via HAR
//   comparison of fixplaybacknoiosantiabuse.har vs newhar.har).
//
//   Fix — fire-and-forget proxy:
//     a) Forward the real att/get?t= request to the YouTube server so the
//        server keeps receiving heartbeats and stays in ATTESTATION_PENDING.
//     b) Return an empty 200 proto body to the client immediately — Field 27
//        is never delivered to the parser, kill timer is never armed.
//
//   Startup att/get calls (no ?t=) are left completely unmodified so
//   experiment flags continue to load normally.
// ---------------------------------------------------------------------------
@interface YTUHDAntiAbuseProtocol : NSURLProtocol
@end

@implementation YTUHDAntiAbuseProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"YTUHDHandled" inRequest:request])
        return NO;
    NSString *host = request.URL.host;
    // iosantiabuse-pa.googleapis.com — all paths
    if ([host hasSuffix:@"iosantiabuse-pa.googleapis.com"])
        return YES;
    // youtubei/v1/att/get — ONLY when the ?t= enforcement token is present.
    // Without ?t= the endpoint loads startup experiment flags; those calls
    // must reach the server so the app initialises correctly.
    if ([host hasSuffix:@"youtubei.googleapis.com"]
        && [request.URL.path hasSuffix:@"/att/get"]
        && [request.URL.query hasPrefix:@"t="])
        return YES;
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [super requestIsCacheEquivalent:a toRequest:b];
}

- (void)startLoading {
    if ([self.request.URL.host hasSuffix:@"iosantiabuse-pa.googleapis.com"]) {
        // Rate-limit: allow one synthetic 200 per kAAMinInterval seconds.
        // Without this gate the synthetic 200 causes C++ to immediately retry
        // in a tight loop (~100 req/s), flooding the FLEX network log.
        //
        // Excess requests receive HTTP 429 + Retry-After so that any
        // HTTP-compliant backoff logic in C++ slows the retry cadence.
        // After one successful exchange C++ should not need another for
        // many seconds; the 10 s window is conservative.
        static os_unfair_lock aaLock = OS_UNFAIR_LOCK_INIT;
        static CFAbsoluteTime aaNextAllowed = 0;
        static const CFTimeInterval kAAMinInterval = 10.0;

        os_unfair_lock_lock(&aaLock);
        CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
        BOOL allowed = (now >= aaNextAllowed);
        if (allowed) aaNextAllowed = now + kAAMinInterval;
        os_unfair_lock_unlock(&aaLock);

        if (allowed) {
            // Proto: field 1 (bytes), length 8, eight zero bytes.
            // C++ sees 200 + non-error proto → "exchange succeeded".
            static const uint8_t kAntiAbuseBody[] = { 0x0a, 0x08, 0, 0, 0, 0, 0, 0, 0, 0 };
            NSData *body = [NSData dataWithBytes:kAntiAbuseBody length:sizeof(kAntiAbuseBody)];
            NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc]
                initWithURL:self.request.URL
                 statusCode:200
                HTTPVersion:@"HTTP/2.0"
               headerFields:@{@"Content-Type":  @"application/x-protobuf",
                              @"Cache-Control": @"no-store"}];
            [self.client URLProtocol:self
                  didReceiveResponse:response
                  cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:body];
            [self.client URLProtocolDidFinishLoading:self];
        } else {
            // 429 tells HTTP clients to back off; Retry-After: 10 gives them
            // the exact window.  Empty proto body — C++ should not parse it
            // as an error, just as "no new data, try later".
            NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc]
                initWithURL:self.request.URL
                 statusCode:429
                HTTPVersion:@"HTTP/2.0"
               headerFields:@{@"Content-Type":  @"application/x-protobuf",
                              @"Retry-After":   @"10",
                              @"Cache-Control": @"no-store"}];
            [self.client URLProtocol:self
                  didReceiveResponse:response
                  cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:[NSData data]];
            [self.client URLProtocolDidFinishLoading:self];
        }
        return;
    }

    // att/get?t= — fire-and-forget proxy:
    //
    // 1. Forward the real request to YouTube's server (tagged YTUHDHandled so
    //    this protocol doesn't intercept its own side-channel request).  The
    //    server receives the attestation heartbeat and stays in
    //    ATTESTATION_PENDING, continuing to push media chunks.
    //
    // 2. Immediately return an empty 200 to the calling YouTube code.  Field 27
    //    (the enforcement blob) is never present in an empty response, so the
    //    kill timer is never armed.
    //
    // The side-channel session is created once and reused; it uses the default
    // session configuration which also gets our protocolClasses injected, but
    // the YTUHDHandled property prevents re-entry.

    // -- Step 1: fire-and-forget the real request --
    static NSURLSession *sideChannel;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Use default configuration (ephemeral would skip disk cache, fine either way).
        NSURLSessionConfiguration *cfg =
            [NSURLSessionConfiguration defaultSessionConfiguration];
        sideChannel = [NSURLSession sessionWithConfiguration:cfg];
    });

    NSMutableURLRequest *realReq = [self.request mutableCopy];
    // Tag it so canInitWithRequest: returns NO and the request goes straight
    // to the network without being caught by this protocol again.
    [NSURLProtocol setProperty:@YES forKey:@"YTUHDHandled" inRequest:realReq];
    [[sideChannel dataTaskWithRequest:realReq completionHandler:
        ^(NSData *d, NSURLResponse *r, NSError *e) { /* discard — server ack only */ }
    ] resume];

    // -- Step 2: return empty proto to the client --
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc]
        initWithURL:self.request.URL
         statusCode:200
        HTTPVersion:@"HTTP/2.0"
       headerFields:@{@"Content-Type":  @"application/x-protobuf",
                      @"Cache-Control": @"no-store"}];
    [self.client URLProtocol:self
          didReceiveResponse:response
          cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:[NSData data]];
    [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {}

@end

// Inject YTUHDAntiAbuseProtocol into every NSURLSessionConfiguration so the
// iosantiabuse and att/get intercepts are active for all sessions YouTube
// creates, including custom/ephemeral ones that ignore registerClass:.
%hook NSURLSessionConfiguration
- (NSArray *)protocolClasses {
    NSMutableArray *classes = [[NSMutableArray alloc] initWithArray:(%orig ?: @[])];
    Class antiAbuse = [YTUHDAntiAbuseProtocol class];
    if (![classes containsObject:antiAbuse]) [classes insertObject:antiAbuse atIndex:0];
    return classes;
}
%end

// ---------------------------------------------------------------------------
// PO Token bypass
//
// Confirmed via HAR: LiveContainer2 Team ID LSMHR68PG6 is embedded in the
// Apple AppAttest payload sent to iosantiabuse-pa.googleapis.com/v1/exchange.
// The NSURLProtocol intercept above prevents the 400 from ever reaching C++.
// The hooks below are belt-and-suspenders for any code paths that bypass the
// URL loading system, and to prevent the token manager from spinning up and
// making unnecessary attestation requests.
//
// Fix A: Disable PO token system via YTHotConfig flags (primary).
// Fix B: Strip error from attestation response handler (fallback).
// ---------------------------------------------------------------------------
%hook YTHotConfig
// Kill-switch: disable the entire iOS PO token system.
- (BOOL)iosClientGlobalConfigDisableIosPoTokens { return YES; }
// Prevent the PO token manager from initialising at app startup.
- (BOOL)iosPlayerClientSharedConfigEnablePoTokenManagerInitializationOnStartup { return NO; }
// Delay minter initialisation indefinitely — belt-and-suspenders for startup.
- (BOOL)iosPlayerClientSharedConfigDelayPoTokenMinterInitialization { return YES; }
// Disable per-format-type PO token injection and CABR mode.
- (BOOL)iosPlayerClientSharedConfigEnablePoTokenManagerMedia { return NO; }
- (BOOL)iosPlayerClientSharedConfigEnablePoTokenManagerInjection { return NO; }
- (BOOL)iosPlayerClientSharedConfigIosSpsEnablePoTokenCabr { return NO; }
// If a stored challenge exists, reuse it (prevents new iosantiabuse calls
// on session restarts triggered by seeks).
- (BOOL)iosPlayerClientSharedConfigShouldReuseIosguardChallengeForAttestation { return YES; }
// Prevent the mid-playback iosguard refresh that fires ~15s into a stream.
// Confirmed via HAR: a second iosantiabuse call appears at t+15s during active
// playback.  That 400 response caches a fresh "token invalid" C++ state which
// is read when the next SABR session starts after a seek → triggers the
// 10-second watchtime kill on the restarted session.
- (BOOL)iosPlayerClientSharedConfigRequestIosguardDataAfterPlaybackStarts { return NO; }
%end

%hook iOSGuardManager
// Disabling attestation globally prevents iOSGuard from ever requesting a
// challenge via iosantiabuse-pa.googleapis.com.  Without a challenge request
// the 400 "Precondition check failed" response is never received, so the C++
// SABR session manager never caches a "token invalid" state.  That cached
// state is what causes seek-triggered SABR restarts to kill the stream after
// ~5 seconds — the restart reads the cached failure and starts a kill timer
// without re-calling IGDPOTokenMinter.mintPOTokenImmediately:.
- (BOOL)isIosguardAttestationEnabled { return NO; }
%end

%hook YTIOSGuardSnapshotControllerImpl
// Intercept the iosantiabuse response handler.  When isIosguardAttestationEnabled
// returns NO (iOSGuardManager hook above) this method should never be reached
// at all.  This hook is kept as a belt-and-suspenders fallback.
//
// Previously this was a pure no-op (completion handler never called), which
// left the caller in an indefinite wait — the caller's own 5-second callback
// timeout then fired and killed the SABR stream through a secondary path.
// Now we call completionHandler(nil, nil): "completed with no snapshot and no
// error."  The caller skips the failure branch and the kill timer is not armed.
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
// Intercept every minting call and report a successful (but empty) token.
// GVS does not enforce PO token values server-side — all videoplayback
// segments return 200 regardless.  The only check is whether the internal
// token state is non-nil; supplying empty NSData satisfies that check and
// prevents the ~5 s "no token available" SABR grace-timer from firing.
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
- (void)mintUninitializedPoToken:(id)token initializationCalled:(BOOL)initializationCalled {
    // no-op — never report an uninitialised-token error
}
%end

// ---------------------------------------------------------------------------
// HLS stream availability
//
// When AVPlayer mode is active (renderViewType=2) the player uses
// hlsManifestUrl from the IOS client response.  MLHLSStreamSelector loads
// the master playlist and notifies its delegate so the quality selector UI
// can populate.
//
// KVC key @"_completeMasterPlaylist" was renamed in 21.20.4 and returns nil,
// so the delegate was called with an empty array.  Use arg1 directly instead.
// ---------------------------------------------------------------------------
%hook MLHLSStreamSelector
- (void)didLoadHLSMasterPlaylist:(MLHLSMasterPlaylist *)playlist {
    %orig;
    NSArray *variants = [playlist remotePlaylists];
    if (variants.count > 0)
        [[self delegate] streamSelectorHasSelectableVideoFormats:variants];
}
%end

// ---------------------------------------------------------------------------
// Code=2 safety net
//
// YouTube's player framework checks adaptiveFormats during stream-setup.
// If renderViewType=2 is set correctly and the pool creates a proper
// MLAVPlayer, this error should never fire.  The hook is kept as a safety
// net in case the framework still raises it for an unrelated reason.
// ---------------------------------------------------------------------------
%hook YTMainAppVideoPlayerOverlayViewController
- (void)handleError:(NSError *)error {
    if (FixPlayback()) {
        // Always log errors to Documents so we can see what HAMPlayer reports
        // even when the error UI is suppressed.  Open ytuhd_error_*.txt in FLEX.
        @try {
            NSString *docs = NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES)[0];
            NSString *msg = [NSString stringWithFormat:
                @"ytuhd_error %@\ndomain=%@  code=%ld\n%@\n",
                [NSDate date], error.domain, (long)error.code,
                error.userInfo ?: @{}];
            NSString *name = [NSString stringWithFormat:@"ytuhd_error_%@.txt",
                ytuhd_timestamp()];
            [msg writeToFile:[docs stringByAppendingPathComponent:name]
                  atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } @catch (...) {}
    }
    %orig;
}
%end

%ctor {
    if (!FixPlayback()) return;
    %init;
    // Belt-and-suspenders registration for NSURLConnection and any session
    // using the default URL loading system (complements the configuration hook).
    [NSURLProtocol registerClass:[YTUHDAntiAbuseProtocol class]];

    // Runtime enumeration: replace hasPoToken and isIosguardAttestationEnabled
    // on every ObjC class that implements them, regardless of class name.
    //
    // We run the sweep TWICE:
    //
    // 1. Synchronously here in %ctor — catches regular ObjC classes that are
    //    already registered at dylib-load time (including iOSGuardManager and
    //    related classes).  This ensures the replacement is in place before any
    //    YouTube initialisation code runs, preventing iosantiabuse calls from
    //    firing in the window between dyld and the first run-loop tick.
    //    Without this sync pass those early calls create the 100-req/s loop that
    //    floods the FLEX network log.
    //
    // 2. Async on the main queue — catches proto-generated GPBMessage subclasses
    //    that are registered lazily after UIApplicationMain returns control.
    //    hasPoToken is generated by the proto compiler and lives on such a class.

    SEL hasPoTokenSel        = @selector(hasPoToken);
    SEL isIosguardEnabledSel = @selector(isIosguardAttestationEnabled);

    IMP yesIMP = imp_implementationWithBlock(^BOOL(__unused id _self) { return YES; });
    IMP noIMP  = imp_implementationWithBlock(^BOOL(__unused id _self) { return NO;  });

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
            }
            free(methods);
        }
        free(classes);
    };

    sweep(); // synchronous — blocks early iosantiabuse calls at dyld-init time
    dispatch_async(dispatch_get_main_queue(), sweep); // catches GPB classes registered later
}
