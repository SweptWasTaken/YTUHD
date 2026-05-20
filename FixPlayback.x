// Adapted from YouPiP by PoomSmart
// Updated for YouTube 21.20.4 - removed dead hooks, fixed signatures
// TVHTML5 client spoofing via NSMutableURLRequest to obtain hlsManifestUrl

#import <Foundation/Foundation.h>
#import <YouTubeHeader/MLAVPlayer.h>
#import <YouTubeHeader/MLDefaultPlayerViewFactory.h>
#import <YouTubeHeader/MLPlayerPool.h>
#import <YouTubeHeader/MLPlayerPoolImpl.h>
#import <YouTubeHeader/MLVideoDecoderFactory.h>
#import <YouTubeHeader/YTHotConfig.h>
#import "Header.h"

extern BOOL FixPlayback();

@interface YTGLMediaPlayerViewFactory : NSObject
@end

static MLAVPlayer *makeAVPlayer(id self, MLVideo *video, MLInnerTubePlayerConfig *playerConfig, MLPlayerStickySettings *stickySettings) {
    BOOL externalPlaybackActive = [(MLAVPlayer *)[self valueForKey:@"_activePlayer"] externalPlaybackActive];
    MLAVPlayer *player = [[%c(MLAVPlayer) alloc] initWithVideo:video playerConfig:playerConfig stickySettings:stickySettings externalPlaybackActive:externalPlaybackActive];
    if (stickySettings)
        player.rate = stickySettings.rate;
    return player;
}

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

// Only surviving signature in 21.20.4
- (id)acquirePlayerForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig stickySettings:(MLPlayerStickySettings *)stickySettings latencyLogger:(id)latencyLogger reloadContext:(id)reloadContext mediaPlayerResources:(id)mediaPlayerResources recompositeProvider:(id)recompositeProvider {
    return makeAVPlayer(self, video, playerConfig, stickySettings);
}

// Updated: only mediaPlayerResources: variant exists in 21.20.4
- (MLAVPlayerLayerView *)playerViewForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig mediaPlayerResources:(id)mediaPlayerResources {
    MLDefaultPlayerViewFactory *factory = [self valueForKey:@"_playerViewFactory"];
    return [factory AVPlayerViewForVideo:video playerConfig:playerConfig];
}

// Only surviving canQueuePlayerPlay signature in 21.20.4
- (BOOL)canQueuePlayerPlayVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig reloadContext:(id)reloadContext error:(NSError **)error {
    return NO;
}

- (BOOL)canUsePlayerView:(id)playerView forPlayerConfig:(MLInnerTubePlayerConfig *)playerConfig {
    forceRenderViewTypeBase([playerConfig hamplayerConfig]);
    return %orig;
}

%end

%hook MLPlayerPool

// Only surviving signature in 21.20.4
- (id)acquirePlayerForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig stickySettings:(MLPlayerStickySettings *)stickySettings latencyLogger:(id)latencyLogger reloadContext:(id)reloadContext mediaPlayerResources:(id)mediaPlayerResources recompositeProvider:(id)recompositeProvider {
    return makeAVPlayer(self, video, playerConfig, stickySettings);
}

// Updated: only mediaPlayerResources: variant exists in 21.20.4
- (MLAVPlayerLayerView *)playerViewForVideo:(MLVideo *)video playerConfig:(MLInnerTubePlayerConfig *)playerConfig mediaPlayerResources:(id)mediaPlayerResources {
    MLDefaultPlayerViewFactory *factory = [self valueForKey:@"_playerViewFactory"];
    return [factory AVPlayerViewForVideo:video playerConfig:playerConfig];
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
// Client type spoofing: IOS → TVHTML5
//
// The IOS client's /youtubei/v1/player response contains DASH streams only;
// TVHTML5 receives hlsManifestUrl instead, which AVPlayer can consume without
// a PO Token. The request body is JSON even though transport is QUIC (Cronet
// uses the NSMutableURLRequest body data directly), so this hook fires before
// the transport layer and rewrites the body in-place.
// ---------------------------------------------------------------------------

static NSData *spoofClientInBody(NSData *bodyData) {
    if (!bodyData || bodyData.length == 0) return bodyData;
    NSError *err = nil;
    id parsed = [NSJSONSerialization JSONObjectWithData:bodyData
                                               options:NSJSONReadingMutableContainers
                                                 error:&err];
    if (err || ![parsed isKindOfClass:[NSMutableDictionary class]]) return bodyData;
    NSMutableDictionary *body   = (NSMutableDictionary *)parsed;
    NSMutableDictionary *ctx    = body[@"context"];
    NSMutableDictionary *client = ctx[@"client"];
    if (![client isKindOfClass:[NSMutableDictionary class]]) return bodyData;
    if (![client[@"clientName"] isEqualToString:@"IOS"])     return bodyData;
    client[@"clientName"]    = @"TVHTML5";
    client[@"clientVersion"] = @"7.20240918.01.00";
    [client removeObjectForKey:@"deviceMake"];
    [client removeObjectForKey:@"deviceModel"];
    [client removeObjectForKey:@"osName"];
    [client removeObjectForKey:@"osVersion"];
    [client removeObjectForKey:@"deviceExperimentId"];
    NSData *result = [NSJSONSerialization dataWithJSONObject:body options:0 error:&err];
    return err ? bodyData : result;
}

%hook NSMutableURLRequest

- (void)setHTTPBody:(NSData *)data {
    if (data.length > 0 && [self.URL.path containsString:@"/youtubei/v1/player"]) {
        NSData *spoofed = spoofClientInBody(data);
        if (spoofed && spoofed != data) {
            [self setValue:@"7"                forHTTPHeaderField:@"X-Youtube-Client-Name"];
            [self setValue:@"7.20240918.01.00" forHTTPHeaderField:@"X-Youtube-Client-Version"];
            %orig(spoofed);
            return;
        }
    }
    %orig;
}

%end

%ctor {
    if (!FixPlayback()) return;
    %init;
}
