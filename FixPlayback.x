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
// YouTube's GVS requires a PO Token for DASH from the IOS client. Sideloaded
// apps can't generate valid tokens (needs DeviceCheck/AppAttest). TVHTML5
// clients receive hlsManifestUrl in streamingData instead of DASH segments;
// HLS does not require a PO Token.
//
// Implementation: NSURLProtocol subclass injected into every NSURLSession's
// protocolClasses list. This catches requests regardless of session
// configuration or subclassing — the previous approach (hooking instance
// methods on NSURLSession) missed YouTube's custom-configured sessions.
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

// Reads the HTTP body from either HTTPBody (NSData) or HTTPBodyStream.
// Consuming the stream is fine here because we always replace it with NSData
// on the mutable copy we forward.
static NSData *readHTTPBody(NSURLRequest *req) {
    if (req.HTTPBody) return req.HTTPBody;
    NSInputStream *s = req.HTTPBodyStream;
    if (!s) return nil;
    [s open];
    NSMutableData *buf = [NSMutableData dataWithCapacity:8192];
    uint8_t tmp[4096]; NSInteger n;
    while ([s hasBytesAvailable] && (n = [s read:tmp maxLength:sizeof(tmp)]) > 0)
        [buf appendBytes:tmp length:n];
    [s close];
    return buf.length ? buf : nil;
}

static NSString *const kSpoofed = @"YTSpoofed";

// ---- NSURLProtocol subclass ------------------------------------------------

@interface YTClientSpoofProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSession *fwdSession;
@property (nonatomic, strong) NSURLSessionDataTask *fwdTask;
@end

@implementation YTClientSpoofProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)req {
    if (![req.URL.path containsString:@"/youtubei/v1/player"]) return NO;
    if ([NSURLProtocol propertyForKey:kSpoofed inRequest:req])  return NO;
    return YES;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)req { return req; }
+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [super requestIsCacheEquivalent:a toRequest:b];
}

- (void)startLoading {
    NSMutableURLRequest *mod = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:kSpoofed inRequest:mod];

    [mod setValue:@"7"                  forHTTPHeaderField:@"X-Youtube-Client-Name"];
    [mod setValue:@"7.20240918.01.00"   forHTTPHeaderField:@"X-Youtube-Client-Version"];

    NSData *newBody = spoofClientInBody(readHTTPBody(self.request));
    if (newBody) {
        [mod setHTTPBody:newBody];
        [mod setValue:[NSString stringWithFormat:@"%lu", (unsigned long)newBody.length]
   forHTTPHeaderField:@"Content-Length"];
    }

    // Use an ephemeral config with an empty protocol list so this forwarded
    // request is NOT re-intercepted by our own protocol.
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.protocolClasses = @[];
    self.fwdSession = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    self.fwdTask    = [self.fwdSession dataTaskWithRequest:mod];
    [self.fwdTask resume];
}

- (void)stopLoading {
    [self.fwdTask cancel];
    [self.fwdSession invalidateAndCancel];
    self.fwdTask = self.fwdSession = nil;
}

- (void)URLSession:(NSURLSession *)s dataTask:(NSURLSessionDataTask *)t
                             didReceiveResponse:(NSURLResponse *)resp
                             completionHandler:(void (^)(NSURLSessionResponseDisposition))ch {
    [self.client URLProtocol:self didReceiveResponse:resp
          cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    ch(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)s dataTask:(NSURLSessionDataTask *)t
                                didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
}
- (void)URLSession:(NSURLSession *)s task:(NSURLSessionTask *)t
                        didCompleteWithError:(NSError *)err {
    if (err) [self.client URLProtocol:self didFailWithError:err];
    else     [self.client URLProtocolDidFinishLoading:self];
}
- (void)URLSession:(NSURLSession *)s task:(NSURLSessionTask *)t
        willPerformHTTPRedirection:(NSHTTPURLResponse *)resp
                        newRequest:(NSURLRequest *)req
                 completionHandler:(void (^)(NSURLRequest *))ch {
    [self.client URLProtocol:self wasRedirectedToRequest:req redirectResponse:resp];
    ch(req);
}

@end

// ---- Inject into every NSURLSession ----------------------------------------
// Globally-registered protocols are ignored by sessions with custom configs,
// so we hook the factory class methods to insert our protocol into every
// session's protocolClasses list at creation time.

static void injectProtocol(NSURLSessionConfiguration *cfg) {
    if (!cfg) return;
    NSMutableArray *list = [(cfg.protocolClasses ?: @[]) mutableCopy];
    if (![list containsObject:[YTClientSpoofProtocol class]]) {
        [list insertObject:[YTClientSpoofProtocol class] atIndex:0];
        cfg.protocolClasses = list;
    }
}

%hook NSURLSession

+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration
                                  delegate:(id)delegate
                             delegateQueue:(NSOperationQueue *)queue {
    NSURLSessionConfiguration *cfg = [configuration copy];
    injectProtocol(cfg);
    return %orig(cfg, delegate, queue);
}

+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration {
    NSURLSessionConfiguration *cfg = [configuration copy];
    injectProtocol(cfg);
    return %orig(cfg);
}

%end

%ctor {
    if (!FixPlayback()) return;
    // Cover the shared session ([NSURLSession sharedSession]) too.
    [NSURLProtocol registerClass:[YTClientSpoofProtocol class]];
    %init;
}
