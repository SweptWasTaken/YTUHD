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

static void forceRenderViewTypeHot(YTIHamplayerHotConfig *hamplayerHotConfig) {
    if (!hamplayerHotConfig) return;
    hamplayerHotConfig.renderViewType = 2;
}

static void forceRenderViewType(YTHotConfig *hotConfig) {
    YTIHamplayerHotConfig *hamplayerHotConfig = [hotConfig hamplayerHotConfig];
    forceRenderViewTypeHot(hamplayerHotConfig);
}

%hook MLPlayerPoolImpl

// Force renderViewType=2 on playerConfig BEFORE the pool creates its player.
// In 21.20.4 the pool passes mediaPlayerResources + recompositeProvider to
// the player init, which are required for the player to load any URL.
// Previously we called makeAVPlayer() here which skipped those arguments,
// producing a player that was never wired up → Code=2 immediately.
- (id)acquirePlayerForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig stickySettings:(MLPlayerStickySettings *)stickySettings latencyLogger:(id)latencyLogger reloadContext:(id)reloadContext mediaPlayerResources:(id)mediaPlayerResources recompositeProvider:(id)recompositeProvider {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (id)playerViewForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig mediaPlayerResources:(id)mediaPlayerResources {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (BOOL)canQueuePlayerPlayVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig reloadContext:(id)reloadContext error:(NSError **)error {
    return NO;
}

- (BOOL)canUsePlayerView:(id)playerView forPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

%end

%hook MLPlayerPool

- (id)acquirePlayerForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig stickySettings:(MLPlayerStickySettings *)stickySettings latencyLogger:(id)latencyLogger reloadContext:(id)reloadContext mediaPlayerResources:(id)mediaPlayerResources recompositeProvider:(id)recompositeProvider {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (id)playerViewForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig mediaPlayerResources:(id)mediaPlayerResources {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (BOOL)canUsePlayerView:(id)playerView forVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (BOOL)canQueuePlayerPlayVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig reloadContext:(id)reloadContext error:(NSError **)error {
    return NO;
}

%end

%hook MLDefaultPlayerViewFactory

- (id)hamPlayerViewForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewType([self valueForKey:@"_hotConfig"]);
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (id)hamPlayerViewForPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewType([self valueForKey:@"_hotConfig"]);
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (id)AVPlayerViewForPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewType([self valueForKey:@"_hotConfig"]);
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (BOOL)canUsePlayerView:(id)playerView forVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (BOOL)canUsePlayerView:(id)playerView forPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

%end

%hook MLVideoDecoderFactory

- (void)prepareDecoderForFormatDescription:(id)formatDescription delegateQueue:(id)delegateQueue {
    forceRenderViewTypeHot([self valueForKey:@"_hotConfig"]);
    %orig;
}

- (void)prepareDecoderForFormatDescription:(id)formatDescription setPixelBufferTypeOnlyIfEmpty:(BOOL)setPixelBufferTypeOnlyIfEmpty delegateQueue:(id)delegateQueue {
    forceRenderViewTypeHot([self valueForKey:@"_hotConfig"]);
    %orig;
}

%end

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
// OnesieRequest entirely and fall back to client-side ABR.  Client-side ABR
// on iOS uses the hlsManifestUrl provided by the /youtubei/v1/player API
// response.  HLS segment requests to GVS currently do NOT require PO token
// validation, so the stream plays without any attestation machinery.
//
// Combined with renderViewType=2 (AVPlayer renderer) the complete stack is:
//   AVPlayer + HLS manifest → GVS HLS segments → no SABR → no PO token → ✓
// ---------------------------------------------------------------------------
%hook YTIMediaCommonConfig
- (BOOL)useServerDrivenAbr { return NO; }
%end

%hook YTGLMediaPlayerViewFactory

- (BOOL)canUsePlayerView:(id)playerView forPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (id)hamPlayerViewForPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewType([self valueForKey:@"_hotConfig"]);
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (id)AVPlayerViewForPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewType([self valueForKey:@"_hotConfig"]);
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

- (id)viewForPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewType([self valueForKey:@"_hotConfig"]);
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

%end

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
                if (![fmt isKindOfClass:[MLFormat class]]) return YES;
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
        // Proto: field 1 (bytes), length 8, eight zero bytes.
        // C++ sees 200 + non-error proto → "exchange succeeded".
        // Token value is never validated client-side or server-side.
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

// Inject YTUHDAntiAbuseProtocol into every NSURLSessionConfiguration so it
// is active for all NSURLSession instances YouTube creates, including custom
// and ephemeral sessions that ignore +[NSURLProtocol registerClass:].
%hook NSURLSessionConfiguration
- (NSArray *)protocolClasses {
    NSMutableArray *classes = [[NSMutableArray alloc] initWithArray:(%orig ?: @[])];
    Class proto = [YTUHDAntiAbuseProtocol class];
    if (![classes containsObject:proto])
        [classes insertObject:proto atIndex:0];
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
    if (FixPlayback()
        && [error.domain isEqualToString:@"com.google.ios.youtube.ErrorDomain.playback"]
        && (error.code == 2   // "No stream" — AVPlayer found no HLS URL
            || error.code == 14)) // "Something went wrong" — PO token grace-timer abort
        return;
    %orig;
}
%end

%ctor {
    if (!FixPlayback()) return;
    %init;
    // Belt-and-suspenders registration for NSURLConnection and any session
    // using the default URL loading system (complements the configuration hook).
    [NSURLProtocol registerClass:[YTUHDAntiAbuseProtocol class]];

    // Runtime enumeration: hook hasPoToken and isIosguardAttestationEnabled on
    // every ObjC class that has them, regardless of class name.
    //
    // WHY dispatch_async instead of running inline in %ctor:
    // %ctor runs at dyld initialiser time — before the main run loop starts and
    // before many proto-generated GPBMessage subclasses have been registered
    // with the ObjC runtime.  class_copyMethodList at that point misses those
    // classes, so the replacement never lands.  Dispatching to the main queue
    // defers until the first main-run-loop tick (i.e. after UIApplicationMain
    // returns control, well before the user can open any video).  By that point
    // 100% of ObjC classes are registered and all +initialize methods have run.
    //
    // hasPoToken: proto-generated presence check fired at the 10-second watchtime
    // mark.  Returning YES prevents the SABR kill timer from arming.
    //
    // isIosguardAttestationEnabled: returning NO stops iOSGuard from ever issuing
    // an iosantiabuse challenge request.  The static %hook iOSGuardManager covers
    // the expected name; this sweep catches any differently-named class.
    dispatch_async(dispatch_get_main_queue(), ^{
        SEL hasPoTokenSel        = @selector(hasPoToken);
        SEL isIosguardEnabledSel = @selector(isIosguardAttestationEnabled);

        IMP yesIMP = imp_implementationWithBlock(^BOOL(__unused id _self) { return YES; });
        IMP noIMP  = imp_implementationWithBlock(^BOOL(__unused id _self) { return NO;  });

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
    });
}
