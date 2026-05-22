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
// PO Token bypass
//
// Confirmed via HAR: LiveContainer2 Team ID LSMHR68PG6 is embedded in the
// Apple AppAttest payload sent to iosantiabuse-pa.googleapis.com/v1/exchange.
// Google rejects it (400 "Precondition check failed.") because it's not
// YouTube's real Team ID.  After 9 consecutive 400s the YouTube app aborts
// the SABR stream (status 999) and shows Code=14.  GVS CDN serves all
// segments at 200 without PO token enforcement — the app itself kills.
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
