// Adapted from YouPiP by PoomSmart
// Updated for YouTube 21.20.4 - removed dead hooks, fixed signatures
// Client type spoofing added: IOS → TVHTML5 so backend returns hlsManifestUrl

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

// Remove 2K, 4K and HDR options since they don't work without VP9 entitlements on sideloaded apps
%hook MLHLSStreamSelector

- (void)didLoadHLSMasterPlaylist:(id)arg1 {
    %orig;
    MLHLSMasterPlaylist *playlist = [self valueForKey:@"_completeMasterPlaylist"];
    NSArray *remotePlaylists = [playlist remotePlaylists];
    NSMutableArray *filter = [NSMutableArray array];
    for (MLFormat *formats in remotePlaylists) {
        NSString *label = [formats qualityLabel];
        if ([label containsString:@"HDR"]) continue;
        if ([label containsString:@"2160p"]) continue;
        if ([label containsString:@"1440p"]) continue;
        [filter addObject:formats];
    }
    [[self delegate] streamSelectorHasSelectableVideoFormats:filter];
}

%end

// ---------------------------------------------------------------------------
// Client type spoofing: IOS → TVHTML5
//
// YouTube's Google Video Server requires a Proof-of-Origin (PO) Token for
// DASH streams served to the IOS client. Sideloaded apps can't generate
// a valid token (needs DeviceCheck/AppAttest). TVHTML5 clients receive an
// HLS manifest URL (hlsManifestUrl) in the streamingData instead of DASH
// segments, and HLS currently does NOT require a PO Token.
//
// We intercept the /youtubei/v1/player POST request body, change clientName
// from "IOS" to "TVHTML5" and bump clientVersion to match. The server then
// returns hlsManifestUrl, which populates the mlhls:// chain used by
// MLAVAssetDownloader → AVPlayer, allowing playback without a PO Token.
// ---------------------------------------------------------------------------

static BOOL isPlayerEndpoint(NSURL *url) {
    return [url.path containsString:@"/youtubei/v1/player"];
}

// Parse bodyData as JSON, swap IOS → TVHTML5, return modified bytes.
// Returns the original bodyData unchanged on any parse/serialisation error.
static NSData *spoofClientInBody(NSData *bodyData) {
    if (!bodyData || bodyData.length == 0) return bodyData;
    NSError *err = nil;
    id parsed = [NSJSONSerialization JSONObjectWithData:bodyData
                                               options:NSJSONReadingMutableContainers
                                                 error:&err];
    if (err || ![parsed isKindOfClass:[NSMutableDictionary class]]) return bodyData;
    NSMutableDictionary *body = (NSMutableDictionary *)parsed;
    id ctxObj = body[@"context"];
    if (![ctxObj isKindOfClass:[NSMutableDictionary class]]) return bodyData;
    NSMutableDictionary *context = (NSMutableDictionary *)ctxObj;
    id clientObj = context[@"client"];
    if (![clientObj isKindOfClass:[NSMutableDictionary class]]) return bodyData;
    NSMutableDictionary *client = (NSMutableDictionary *)clientObj;
    // Only spoof when the original client is IOS; leave anything else alone.
    if (![client[@"clientName"] isEqualToString:@"IOS"]) return bodyData;
    client[@"clientName"] = @"TVHTML5";
    client[@"clientVersion"] = @"7.20240918.01.00";
    // Strip iOS-specific context fields that don't belong in a TVHTML5 request.
    [client removeObjectForKey:@"deviceMake"];
    [client removeObjectForKey:@"deviceModel"];
    [client removeObjectForKey:@"osName"];
    [client removeObjectForKey:@"osVersion"];
    [client removeObjectForKey:@"deviceExperimentId"];
    NSData *result = [NSJSONSerialization dataWithJSONObject:body options:0 error:&err];
    return err ? bodyData : result;
}

// Return a modified copy of request with TVHTML5 body + headers,
// or the original request if it isn't a player endpoint.
static NSURLRequest *spoofedPlayerRequest(NSURLRequest *request) {
    if (!isPlayerEndpoint(request.URL)) return request;
    NSMutableURLRequest *mutable = [request mutableCopy];
    // Always update the client-identifying headers.
    [mutable setValue:@"7" forHTTPHeaderField:@"X-Youtube-Client-Name"];
    [mutable setValue:@"7.20240918.01.00" forHTTPHeaderField:@"X-Youtube-Client-Version"];
    // Modify the JSON body when it was provided inline (most InnerTube calls).
    NSData *origBody = request.HTTPBody;
    NSData *newBody = spoofClientInBody(origBody);
    if (newBody && newBody != origBody) {
        [mutable setHTTPBody:newBody];
        [mutable setValue:[NSString stringWithFormat:@"%lu", (unsigned long)newBody.length]
       forHTTPHeaderField:@"Content-Length"];
    }
    return mutable;
}

%hook NSURLSession

// Standard data task (inline body via HTTPBody — used by YouTube's InnerTube).
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    return %orig(spoofedPlayerRequest(request), completionHandler);
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    return %orig(spoofedPlayerRequest(request));
}

// Upload task variant (body passed separately — defensive hook in case YouTube
// ever sends the player request as an upload task).
- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request
                                         fromData:(NSData *)bodyData
                               completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    if (isPlayerEndpoint(request.URL)) {
        NSMutableURLRequest *mutable = [request mutableCopy];
        [mutable setValue:@"7" forHTTPHeaderField:@"X-Youtube-Client-Name"];
        [mutable setValue:@"7.20240918.01.00" forHTTPHeaderField:@"X-Youtube-Client-Version"];
        return %orig(mutable, spoofClientInBody(bodyData), completionHandler);
    }
    return %orig;
}

%end

%ctor {
    if (!FixPlayback()) return;
    %init;
}
