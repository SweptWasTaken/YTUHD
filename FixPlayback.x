// Adapted from YouPiP by PoomSmart
// Updated for YouTube 21.20.4 - removed dead hooks, fixed signatures
//
// Root cause (confirmed via HAR + binary analysis):
//
// 1. makeAVPlayer() was creating MLAVPlayer WITHOUT mediaPlayerResources /
//    recompositeProvider → player never loaded a URL → Code=2 immediately.
//    Fix: set renderViewType=2 then call %orig so the pool creates a fully-
//    initialised player with all resources.
//
// 2. WEB client spoof via setHTTPBody: was a no-op: the /player call goes
//    over QUIC and never touches NSMutableURLRequest.  (Removed.)
//
// 3. (Root cause of Code=14 "Something went wrong", confirmed via HAR)
//    YouTube sends Apple AppAttest tokens to iosantiabuse-pa.googleapis.com
//    to obtain PO (Proof of Origin) tokens for GVS authentication.  Inside
//    LiveContainer the AppAttest carries LiveContainer's Team ID
//    (LSMHR68PG6) instead of YouTube's, so every exchange returns
//    400 "Precondition check failed."  After 9 consecutive failures the
//    YouTube app aborts the SABR stream and shows Code=14.
//
//    Critically, GVS CDN is NOT enforcing PO tokens server-side — every
//    segment request returns 200 regardless.  The YouTube app itself is
//    the entity that kills the stream.
//
//    Fix A: Disable the PO token system via YTHotConfig flags so
//    iosantiabuse is never called.
//    Fix B: Hook YTIOSGuardSnapshotControllerImpl to intercept the
//    attestation response handler and strip the error before it reaches
//    the stream-kill logic (belt-and-suspenders fallback).

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
// iosantiabuse network intercept (NSURLProtocol)
//
// Root cause of the 4-second SABR kill (confirmed via HAR analysis):
//
//   iosantiabuse-pa.googleapis.com/v1/exchange returns 400 "Precondition
//   check failed" because LiveContainer2 re-signs YouTube with Team ID
//   LSMHR68PG6 instead of YouTube's real Team ID, so AppAttest fails server-
//   side.  The C++ iosguard layer inside YouTube parses that 400 HTTP status
//   BEFORE any ObjC code runs, and writes a "exchange failed" state into a
//   C++ global.  When the NEXT SABR session starts (e.g. after the user
//   switches videos), the session reads the cached C++ failure and arms a
//   4-second kill timer that bypasses the ObjC hasPoToken check entirely.
//   Confirmed: qoe:mta fires at exactly 4.08 s after video 2 SABR start,
//   while video 1 (whose SABR started BEFORE iosantiabuse returned) plays
//   fine.
//
// Fix: intercept at NSURLProtocol level, replacing the 400 with a synthetic
// 200 + minimal proto body before the bytes reach any C++ code.  The C++
// exchange handler sees status 200, transitions to "succeeded", never writes
// the failure state, and no kill timer is armed.
//
// The fake token is proto field 1 (bytes) = 8 zero bytes.  GVS does not
// validate token content server-side — all videoplayback and initplayback
// requests return 200 regardless of token value (confirmed across all HARs).
// ---------------------------------------------------------------------------
@interface YTUHDAntiAbuseProtocol : NSURLProtocol
@end

@implementation YTUHDAntiAbuseProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"YTUHDHandled" inRequest:request])
        return NO;
    return [request.URL.host hasSuffix:@"iosantiabuse-pa.googleapis.com"];
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [super requestIsCacheEquivalent:a toRequest:b];
}

- (void)startLoading {
    // Proto: field 1 (bytes), length 8, eight zero bytes.
    // C++ sees 200 + non-error proto → "exchange succeeded, token = [8 zeros]".
    // Token value is never validated client-side or server-side.
    static const uint8_t kBody[] = { 0x0a, 0x08, 0, 0, 0, 0, 0, 0, 0, 0 };
    NSData *body = [NSData dataWithBytes:kBody length:sizeof(kBody)];
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
