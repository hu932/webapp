#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <substrate.h>
#import <zlib.h>

static NSString * const kSHPBundleID = @"com.beeasy.shopee.tw";
static NSString * const kSHPPrefsDomain = @"com.codex.shopeetaskhook";
static NSString * const kSHPControlURL = @"http://xn--0xvs40a.cn/decrypt_proxy.php";
static NSString * const kSHPLoginURL = @"http://xn--0xvs40a.cn/decrypt_proxy.php";
static NSString * const kSHPTakeTaskURL = @"https://zb1.eqwofaygdsjko.uk/api/task/take";
static NSString * const kSHPApi2TakeTaskURL = @"http://103.143.80.158:2000/get";
static NSString * const kSHPApi2FixedUsername = @"\u7c73\u4e50\u7c73\u4e50";
static NSString * const kSHPSubmitAppVersion = @"vv2";
static NSTimeInterval const kSHPHeartbeatInterval = 30.0;

static NSString * const kSHPDefaultsUsernameKey = @"shp.rebuild.username";
static NSString * const kSHPDefaultsPasswordKey = @"shp.rebuild.password";
static NSString * const kSHPDefaultsTokenKey = @"shp.rebuild.token";
static NSString * const kSHPDefaultsGroupIDKey = @"shp.rebuild.groupID";
static NSString * const kSHPDefaultsApiTypeKey = @"shp.rebuild.apiType";
static NSString * const kSHPDefaultsDeviceIDKey = @"shp.rebuild.deviceID";
static NSString * const kSHPDefaultsRunningKey = @"shp.rebuild.running";
static NSString * const kSHPDefaultsCollapsedKey = @"shp.rebuild.collapsed";
static NSString * const kSHPDefaultsCurrentTaskKey = @"shp.rebuild.currentTask";
static NSString * const kSHPDefaultsSuccessCountKey = @"shp.rebuild.successCount";
static NSString * const kSHPDefaultsPanelWidthKey = @"shp.rebuild.panelWidth";
static NSString * const kSHPDefaultsPanelHeightKey = @"shp.rebuild.panelHeight";
static NSString * const kSHPDefaultsIntervalRangeKey = @"shp.rebuild.intervalRange";
static NSString * const kSHPDefaultsMiniModeKey = @"shp.rebuild.miniMode";
static NSString * const kSHPDefaultsRestEnabledKey = @"shp.rebuild.restEnabled";
static NSString * const kSHPDefaultsRestCountKey = @"shp.rebuild.restCount";
static NSString * const kSHPDefaultsRestMinutesKey = @"shp.rebuild.restMinutes";
static NSString * const kSHPDefaultsLastRestSuccessCountKey = @"shp.rebuild.lastRestSuccessCount";
static BOOL const kSHPEnableShopeeSpecificHooks = NO;
static BOOL SHPGenericHooksInstalled = NO;
static BOOL SHPShopeeSpecificHooksInstalled = NO;

static NSMutableDictionary<NSString *, NSValue *> *SHPOriginalDidReceiveDataIMPMap;
static NSMutableDictionary<NSString *, NSValue *> *SHPOriginalDidCompleteIMPMap;
static IMP SHPOriginalNSURLSessionDataTaskWithRequestIMP = NULL;
static IMP SHPOriginalNSURLSessionDataTaskWithURLIMP = NULL;
static IMP SHPOriginalNSJSONSerializationJSONObjectWithDataIMP = NULL;
static IMP SHPOriginalSessionWithConfigDelegateIMP = NULL;
static void SHPInstallShopeeSpecificHooks(void);

@class SHPPluginController;

static id SHPSharedPluginController(void) {
    Class controllerClass = objc_getClass("SHPPluginController");
    SEL sharedSelector = @selector(shared);
    if (!controllerClass || ![controllerClass respondsToSelector:sharedSelector]) {
        return nil;
    }
    return ((id (*)(id, SEL))objc_msgSend)(controllerClass, sharedSelector);
}

static id SHPPreferencesCopyValue(NSString *key) {
    if (!key.length) {
        return nil;
    }
    return CFBridgingRelease(CFPreferencesCopyAppValue((__bridge CFStringRef)key, (__bridge CFStringRef)kSHPPrefsDomain));
}

static void SHPPreferencesSetValue(NSString *key, id value) {
    if (!key.length) {
        return;
    }
    CFPreferencesSetAppValue((__bridge CFStringRef)key, value ? (__bridge CFPropertyListRef)value : NULL, (__bridge CFStringRef)kSHPPrefsDomain);
}

static void SHPPreferencesSynchronize(void) {
    CFPreferencesAppSynchronize((__bridge CFStringRef)kSHPPrefsDomain);
}

static NSString *SHPStringValue(id value) {
    if (!value || value == [NSNull null]) {
        return nil;
    }
    if ([value isKindOfClass:[NSString class]]) {
        NSString *text = [(NSString *)value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        return text.length ? text : nil;
    }
    if ([value isKindOfClass:[NSNumber class]]) {
        return [(NSNumber *)value stringValue];
    }
    return nil;
}

static id SHPCallNoArgObject(id target, NSString *selectorName) {
    SEL selector = NSSelectorFromString(selectorName);
    if (!target || !selector || ![target respondsToSelector:selector]) {
        return nil;
    }
    return ((id (*)(id, SEL))objc_msgSend)(target, selector);
}

static Class SHPResolveRuntimeClass(NSArray<NSString *> *candidateNames) {
    for (NSString *candidateName in candidateNames) {
        Class candidateClass = NSClassFromString(candidateName);
        if (candidateClass) {
            return candidateClass;
        }
    }

    int classCount = objc_getClassList(NULL, 0);
    if (classCount <= 0) {
        return Nil;
    }

    Class *classes = (Class *)calloc((size_t)classCount, sizeof(Class));
    if (!classes) {
        return Nil;
    }

    classCount = objc_getClassList(classes, classCount);
    Class matchedClass = Nil;
    for (int index = 0; index < classCount && !matchedClass; index++) {
        NSString *runtimeName = NSStringFromClass(classes[index]);
        if (!runtimeName.length) {
            continue;
        }

        for (NSString *candidateName in candidateNames) {
            if (!candidateName.length) {
                continue;
            }

            if ([runtimeName isEqualToString:candidateName] ||
                [runtimeName hasSuffix:candidateName] ||
                [runtimeName containsString:candidateName]) {
                matchedClass = classes[index];
                break;
            }
        }
    }

    free(classes);
    return matchedClass;
}

static IMP SHPOriginalIMPForClass(NSMutableDictionary<NSString *, NSValue *> *map, Class cls) {
    Class currentClass = cls;
    while (currentClass) {
        NSValue *value = map[NSStringFromClass(currentClass)];
        if (value) {
            return (IMP)[value pointerValue];
        }
        currentClass = class_getSuperclass(currentClass);
    }
    return NULL;
}

static BOOL SHPMethodHasVoidReturnAndObjectArguments(Method method, unsigned int objectArgumentCount) {
    if (!method) {
        return NO;
    }

    unsigned int totalArgs = method_getNumberOfArguments(method);
    if (totalArgs != objectArgumentCount + 2) {
        return NO;
    }

    char returnType[16] = {0};
    method_getReturnType(method, returnType, sizeof(returnType));
    if (returnType[0] != 'v') {
        return NO;
    }

    for (unsigned int index = 2; index < totalArgs; index++) {
        char *argType = method_copyArgumentType(method, index);
        BOOL isObject = argType && argType[0] == '@';
        if (argType) {
            free(argType);
        }
        if (!isObject) {
            return NO;
        }
    }

    return YES;
}

static id SHPFindValueForKeys(id object, NSSet<NSString *> *normalizedKeys) {
    if (!object || object == [NSNull null]) {
        return nil;
    }

    if ([object isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)object;
        for (id rawKey in dict.allKeys) {
            if (![rawKey isKindOfClass:[NSString class]]) {
                continue;
            }

            NSString *key = [(NSString *)rawKey lowercaseString];
            if ([normalizedKeys containsObject:key]) {
                return dict[rawKey];
            }
        }

        for (id value in dict.allValues) {
            id found = SHPFindValueForKeys(value, normalizedKeys);
            if (found) {
                return found;
            }
        }
        return nil;
    }

    if ([object isKindOfClass:[NSArray class]]) {
        for (id value in (NSArray *)object) {
            id found = SHPFindValueForKeys(value, normalizedKeys);
            if (found) {
                return found;
            }
        }
    }

    return nil;
}

static NSString *SHPFindStringForKeys(id object, NSArray<NSString *> *keys) {
    NSMutableSet<NSString *> *normalizedKeys = [NSMutableSet setWithCapacity:keys.count];
    for (NSString *key in keys) {
        [normalizedKeys addObject:key.lowercaseString];
    }
    return SHPStringValue(SHPFindValueForKeys(object, normalizedKeys));
}

static NSDictionary *SHPDictionaryValue(id object) {
    if ([object isKindOfClass:[NSDictionary class]]) {
        return (NSDictionary *)object;
    }
    return nil;
}

static NSString *SHPURLStringFromRequestLikeObject(id object) {
    if (!object || object == [NSNull null]) {
        return nil;
    }

    if ([object isKindOfClass:[NSURL class]]) {
        return ((NSURL *)object).absoluteString;
    }

    if ([object isKindOfClass:[NSURLRequest class]]) {
        return ((NSURLRequest *)object).URL.absoluteString;
    }

    NSString *stringValue = SHPStringValue(object);
    if (stringValue.length && [stringValue containsString:@"http"]) {
        return stringValue;
    }

    NSArray<NSString *> *directSelectors = @[@"originalURL", @"URL", @"url", @"serverURL", @"originalUrl"];
    for (NSString *selectorName in directSelectors) {
        id value = SHPCallNoArgObject(object, selectorName);
        if ([value isKindOfClass:[NSURL class]]) {
            return ((NSURL *)value).absoluteString;
        }
        NSString *directString = SHPStringValue(value);
        if (directString.length && [directString containsString:@"http"]) {
            return directString;
        }
    }

    NSArray<NSString *> *nestedSelectors = @[@"currentRequest", @"request", @"URLRequest", @"originalRequest"];
    for (NSString *selectorName in nestedSelectors) {
        NSString *nestedURL = SHPURLStringFromRequestLikeObject(SHPCallNoArgObject(object, selectorName));
        if (nestedURL.length) {
            return nestedURL;
        }
    }

    return nil;
}

static void SHPDispatchOnMainThread(dispatch_block_t block) {
    if (!block) {
        return;
    }

    if ([NSThread isMainThread]) {
        block();
        return;
    }

    dispatch_async(dispatch_get_main_queue(), block);
}

static NSURLSessionDataTask *SHPNSURLSessionDataTaskWithRequestHook(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *data, NSURLResponse *response, NSError *error)) {
    void (^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (completionHandler) {
            completionHandler(data, response, error);
        }
        id controller = SHPSharedPluginController();
        if (controller) {
            ((void (*)(id, SEL, NSData *, NSURLResponse *, NSURLRequest *, NSError *))objc_msgSend)(controller, @selector(inspectResponseData:response:request:error:), data, response, request, error);
        }
    };

    if (SHPOriginalNSURLSessionDataTaskWithRequestIMP) {
        return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))SHPOriginalNSURLSessionDataTaskWithRequestIMP)(self, _cmd, request, wrappedHandler);
    }
    return nil;
}

static NSURLSessionDataTask *SHPNSURLSessionDataTaskWithURLHook(id self, SEL _cmd, NSURL *url, void (^completionHandler)(NSData *data, NSURLResponse *response, NSError *error)) {
    void (^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (completionHandler) {
            completionHandler(data, response, error);
        }
        NSURLRequest *request = url ? [NSURLRequest requestWithURL:url] : nil;
        id controller = SHPSharedPluginController();
        if (controller) {
            ((void (*)(id, SEL, NSData *, NSURLResponse *, NSURLRequest *, NSError *))objc_msgSend)(controller, @selector(inspectResponseData:response:request:error:), data, response, request, error);
        }
    };

    if (SHPOriginalNSURLSessionDataTaskWithURLIMP) {
        return ((NSURLSessionDataTask *(*)(id, SEL, NSURL *, id))SHPOriginalNSURLSessionDataTaskWithURLIMP)(self, _cmd, url, wrappedHandler);
    }
    return nil;
}

static id SHPNSJSONSerializationJSONObjectWithDataHook(id self, SEL _cmd, NSData *data, NSJSONReadingOptions options, NSError **error) {
    id object = nil;
    if (SHPOriginalNSJSONSerializationJSONObjectWithDataIMP) {
        object = ((id (*)(id, SEL, NSData *, NSJSONReadingOptions, NSError **))SHPOriginalNSJSONSerializationJSONObjectWithDataIMP)(self, _cmd, data, options, error);
    }
    id controller = SHPSharedPluginController();
    if (controller) {
        ((void (*)(id, SEL, id, NSData *))objc_msgSend)(controller, @selector(inspectParsedJSONObject:rawData:), object, data);
    }
    return object;
}

static NSString *SHPRegexFirstMatch(NSString *text, NSString *pattern, NSInteger captureIndex) {
    if (!text.length || !pattern.length) {
        return nil;
    }

    NSError *error = nil;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:NSRegularExpressionCaseInsensitive error:&error];
    if (error || !regex) {
        return nil;
    }

    NSTextCheckingResult *result = [regex firstMatchInString:text options:0 range:NSMakeRange(0, text.length)];
    if (!result || captureIndex >= result.numberOfRanges) {
        return nil;
    }

    NSRange range = [result rangeAtIndex:captureIndex];
    if (range.location == NSNotFound || range.length == 0) {
        return nil;
    }

    return [text substringWithRange:range];
}

static NSDictionary<NSString *, NSString *> *SHPExtractIDsFromString(NSString *text) {
    if (!text.length) {
        return @{};
    }

    NSMutableDictionary<NSString *, NSString *> *result = [NSMutableDictionary dictionary];

    NSURLComponents *components = [NSURLComponents componentsWithString:text];
    NSString *path = components.path ?: @"";
    NSArray<NSString *> *pathParts = [path componentsSeparatedByString:@"/"];
    NSMutableArray<NSString *> *filteredParts = [NSMutableArray array];
    for (NSString *part in pathParts) {
        if (part.length) {
            [filteredParts addObject:part];
        }
    }
    if (filteredParts.count >= 3) {
        NSString *marker = filteredParts[0].lowercaseString;
        if ([marker isEqualToString:@"product"]) {
            NSString *shopCandidate = filteredParts[1];
            NSString *itemCandidate = filteredParts[2];
            if (shopCandidate.length && itemCandidate.length) {
                result[@"shop_id"] = shopCandidate;
                result[@"item_id"] = itemCandidate;
            }
        }
    }

    NSString *shopFromProductURL = SHPRegexFirstMatch(text, @"/product/(\\d+)/(\\d+)", 1);
    NSString *itemFromProductURL = SHPRegexFirstMatch(text, @"/product/(\\d+)/(\\d+)", 2);
    if (shopFromProductURL.length && itemFromProductURL.length) {
        result[@"shop_id"] = shopFromProductURL;
        result[@"item_id"] = itemFromProductURL;
    }

    NSString *shopFromCanonicalURL = SHPRegexFirstMatch(text, @"-i\\.(\\d+)\\.(\\d+)", 1);
    NSString *itemFromCanonicalURL = SHPRegexFirstMatch(text, @"-i\\.(\\d+)\\.(\\d+)", 2);
    if (shopFromCanonicalURL.length && itemFromCanonicalURL.length) {
        result[@"shop_id"] = shopFromCanonicalURL;
        result[@"item_id"] = itemFromCanonicalURL;
    }

    NSString *itemQuery = SHPRegexFirstMatch(text, @"(?:item_id|itemid)=([0-9]+)", 1);
    NSString *shopQuery = SHPRegexFirstMatch(text, @"(?:shop_id|shopid)=([0-9]+)", 1);

    if (itemQuery.length) {
        result[@"item_id"] = itemQuery;
    }
    if (shopQuery.length) {
        result[@"shop_id"] = shopQuery;
    }

    return result.copy;
}

static NSDictionary<NSString *, NSString *> *SHPExtractTrailingPathIDs(NSString *text) {
    if (!text.length) {
        return @{};
    }

    NSString *trimmed = [text stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]];
    NSArray<NSString *> *parts = [trimmed componentsSeparatedByString:@"/"];
    if (parts.count < 2) {
        return @{};
    }

    NSString *shopID = SHPStringValue(parts[parts.count - 2]);
    NSString *itemID = SHPStringValue(parts.lastObject);
    NSCharacterSet *digits = [NSCharacterSet decimalDigitCharacterSet];
    BOOL shopNumeric = shopID.length && [[shopID stringByTrimmingCharactersInSet:digits] length] == 0;
    BOOL itemNumeric = itemID.length && [[itemID stringByTrimmingCharactersInSet:digits] length] == 0;
    if (!shopNumeric || !itemNumeric) {
        return @{};
    }
    return @{@"shop_id": shopID, @"item_id": itemID};
}

static NSString *SHPBuildProductURL(NSString *shopID, NSString *itemID) {
    if (!shopID.length || !itemID.length) {
        return nil;
    }
    return [NSString stringWithFormat:@"https://shopee.tw/product/%@/%@", shopID, itemID];
}

static NSString *SHPBuildPDPURL(NSString *shopID, NSString *itemID) {
    if (!shopID.length || !itemID.length) {
        return nil;
    }
    return [NSString stringWithFormat:@"https://shopee.tw/api/v4/pdp/get_pc?display_model_id=0&item_id=%@&model_selection_logic=3&shop_id=%@&tz_offset_in_minutes=480&detail_level=0", itemID, shopID];
}

static NSDictionary<NSString *, NSString *> *SHPExtractPDPMainIDs(id object) {
    NSDictionary *root = SHPDictionaryValue(object);
    if (!root.count) {
        return @{};
    }

    NSDictionary *data = SHPDictionaryValue(root[@"data"]) ?: root;
    NSDictionary *itemData = SHPDictionaryValue(data[@"item_data"]) ?: SHPDictionaryValue(data[@"item"]);
    if (!itemData.count) {
        itemData = SHPDictionaryValue(root[@"item_data"]) ?: SHPDictionaryValue(root[@"item"]);
    }

    NSString *itemID = SHPStringValue(itemData[@"itemid"]) ?: SHPStringValue(itemData[@"item_id"]) ?: SHPStringValue(itemData[@"itemId"]);
    NSString *shopID = SHPStringValue(itemData[@"shopid"]) ?: SHPStringValue(itemData[@"shop_id"]) ?: SHPStringValue(itemData[@"shopId"]);
    if (!itemID.length) {
        itemID = SHPStringValue(data[@"itemid"]) ?: SHPStringValue(data[@"item_id"]) ?: SHPStringValue(data[@"itemId"]);
    }
    if (!shopID.length) {
        shopID = SHPStringValue(data[@"shopid"]) ?: SHPStringValue(data[@"shop_id"]) ?: SHPStringValue(data[@"shopId"]);
    }

    if (!itemID.length || !shopID.length) {
        return @{};
    }
    return @{@"item_id": itemID, @"shop_id": shopID};
}

static NSString *SHPJSONStringFromObject(id object) {
    if (!object || object == [NSNull null]) {
        return nil;
    }
    if (![NSJSONSerialization isValidJSONObject:object]) {
        return SHPStringValue(object);
    }

    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:&error];
    if (error || !data.length) {
        return nil;
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static BOOL SHPObjectHasPDPDetail(id object) {
    NSArray<NSString *> *detailKeys = @[
        @"models",
        @"tier_variations",
        @"price",
        @"price_min",
        @"price_max",
        @"stock",
        @"description",
        @"images",
        @"item_rating",
        @"shop_detailed"
    ];

    NSUInteger detailScore = 0;
    for (NSString *key in detailKeys) {
        id value = SHPFindValueForKeys(object, [NSSet setWithObject:key.lowercaseString]);
        if (!value || value == [NSNull null]) {
            continue;
        }
        if ([value isKindOfClass:[NSArray class]] && [(NSArray *)value count] == 0) {
            continue;
        }
        if ([value isKindOfClass:[NSDictionary class]] && [(NSDictionary *)value count] == 0) {
            continue;
        }
        if ([value isKindOfClass:[NSString class]] && ![(NSString *)value length]) {
            continue;
        }
        detailScore += 1;
    }

    return detailScore >= 3;
}

static BOOL SHPObjectMatchesPDPTask(id object, NSString *shopID, NSString *itemID) {
    if (!shopID.length || !itemID.length) {
        return NO;
    }
    NSDictionary *mainIDs = SHPExtractPDPMainIDs(object);
    NSString *foundItem = mainIDs[@"item_id"];
    NSString *foundShop = mainIDs[@"shop_id"];
    return [foundItem isEqualToString:itemID] && [foundShop isEqualToString:shopID] && SHPObjectHasPDPDetail(object);
}

static id SHPFindMatchingPDPObject(id object, NSString *shopID, NSString *itemID, NSUInteger depth) {
    if (!object || object == [NSNull null] || depth > 8) {
        return nil;
    }
    if (SHPObjectMatchesPDPTask(object, shopID, itemID)) {
        return object;
    }
    if ([object isKindOfClass:[NSDictionary class]]) {
        for (id value in [(NSDictionary *)object allValues]) {
            id found = SHPFindMatchingPDPObject(value, shopID, itemID, depth + 1);
            if (found) {
                return found;
            }
        }
    } else if ([object isKindOfClass:[NSArray class]]) {
        for (id value in (NSArray *)object) {
            id found = SHPFindMatchingPDPObject(value, shopID, itemID, depth + 1);
            if (found) {
                return found;
            }
        }
    }
    return nil;
}

static NSData *SHPGzipData(NSData *data) {
    if (!data.length) {
        return nil;
    }

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return nil;
    }

    NSMutableData *compressed = [NSMutableData dataWithLength:MAX((NSUInteger)16384, data.length / 2)];
    stream.next_in = (Bytef *)data.bytes;
    stream.avail_in = (uInt)data.length;

    int status = Z_OK;
    do {
        if (stream.total_out >= compressed.length) {
            [compressed increaseLengthBy:16384];
        }
        stream.next_out = (Bytef *)compressed.mutableBytes + stream.total_out;
        stream.avail_out = (uInt)(compressed.length - stream.total_out);
        status = deflate(&stream, Z_FINISH);
    } while (status == Z_OK);

    deflateEnd(&stream);
    if (status != Z_STREAM_END) {
        return nil;
    }

    compressed.length = stream.total_out;
    return compressed.copy;
}

@interface SHPPassthroughWindow : UIWindow
@end

@implementation SHPPassthroughWindow

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hitView = [super hitTest:point withEvent:event];
    if (hitView == self || hitView == self.rootViewController.view) {
        return nil;
    }
    return hitView;
}

@end

@interface SHPFallbackNavigationPath : NSObject
@property (nonatomic, copy) NSString *appRL;
+ (instancetype)pathWithAppRL:(NSString *)appRL;
- (instancetype)initWithAppRL:(NSString *)appRL;
@end

@implementation SHPFallbackNavigationPath

+ (instancetype)pathWithAppRL:(NSString *)appRL {
    return [[self alloc] initWithAppRL:appRL];
}

- (instancetype)initWithAppRL:(NSString *)appRL {
    self = [super init];
    if (self) {
        self.appRL = [appRL copy] ?: @"";
    }
    return self;
}

- (NSString *)route {
    return self.appRL;
}

- (NSString *)pathString {
    return self.appRL;
}

- (NSString *)stringValue {
    return self.appRL;
}

- (NSString *)absoluteString {
    return self.appRL;
}

- (NSString *)description {
    return self.appRL ?: @"";
}

@end

@interface SHPTask : NSObject
@property (nonatomic, copy) NSString *traceID;
@property (nonatomic, copy) NSString *itemID;
@property (nonatomic, copy) NSString *shopID;
@property (nonatomic, copy) NSString *productURL;
@property (nonatomic, copy) NSString *pdpURL;
@property (nonatomic, strong) id rawPayload;
- (NSDictionary *)dictionaryRepresentation;
+ (instancetype)taskFromDictionary:(NSDictionary *)dictionary;
@end

@implementation SHPTask

- (NSDictionary *)dictionaryRepresentation {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    if (self.traceID.length) {
        dict[@"traceID"] = self.traceID;
    }
    if (self.itemID.length) {
        dict[@"itemID"] = self.itemID;
    }
    if (self.shopID.length) {
        dict[@"shopID"] = self.shopID;
    }
    if (self.productURL.length) {
        dict[@"productURL"] = self.productURL;
    }
    if (self.pdpURL.length) {
        dict[@"pdpURL"] = self.pdpURL;
    }
    return dict.copy;
}

+ (instancetype)taskFromDictionary:(NSDictionary *)dictionary {
    if (![dictionary isKindOfClass:[NSDictionary class]]) {
        return nil;
    }

    SHPTask *task = [SHPTask new];
    task.traceID = SHPStringValue(dictionary[@"traceID"]);
    task.itemID = SHPStringValue(dictionary[@"itemID"]);
    task.shopID = SHPStringValue(dictionary[@"shopID"]);
    task.productURL = SHPStringValue(dictionary[@"productURL"]);
    task.pdpURL = SHPStringValue(dictionary[@"pdpURL"]);
    return task;
}

@end

@interface SHPPluginController : NSObject <UITextFieldDelegate>
@property (nonatomic, strong) SHPPassthroughWindow *overlayWindow;
@property (nonatomic, strong) UIView *panelView;
@property (nonatomic, strong) UIView *headerView;
@property (nonatomic, strong) UIButton *collapseButton;
@property (nonatomic, strong) UIButton *bubbleButton;
@property (nonatomic, strong) UIView *resizeHandle;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UILabel *taskLabel;
@property (nonatomic, strong) UILabel *counterLabel;
@property (nonatomic, strong) UITextField *usernameField;
@property (nonatomic, strong) UITextField *passwordField;
@property (nonatomic, strong) UIButton *passwordVisibilityButton;
@property (nonatomic, strong) UITextField *intervalField;
@property (nonatomic, strong) UIButton *startTaskButton;
@property (nonatomic, strong) UIButton *resetCountButton;
@property (nonatomic, strong) UIButton *miniModeButton;
@property (nonatomic, strong) UIButton *restModeButton;
@property (nonatomic, strong) UITextField *restCountField;
@property (nonatomic, strong) UITextField *restMinutesField;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UIView *miniView;
@property (nonatomic, strong) UILabel *miniInfoLabel;
@property (nonatomic, strong) NSTimer *countdownTimer;
@property (nonatomic, strong) NSDate *nextFireDate;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) NSTimer *pollTimer;
@property (nonatomic, strong) NSTimer *heartbeatTimer;
@property (nonatomic, strong) SHPTask *currentTask;
@property (nonatomic, copy) NSString *token;
@property (nonatomic, copy) NSString *groupID;
@property (nonatomic, copy) NSString *deviceID;
@property (nonatomic, copy) NSString *pendingSubmitJSONString;
@property (nonatomic, copy) NSString *pendingSubmitSourceURL;
@property (nonatomic, assign) NSInteger successCount;
@property (nonatomic, assign) BOOL isRunning;
@property (nonatomic, assign) BOOL isCollapsed;
@property (nonatomic, assign) BOOL requestInFlight;
@property (nonatomic, assign) BOOL submittingCurrentTask;
@property (nonatomic, assign) BOOL waitingForPDP;
@property (nonatomic, assign) BOOL hasBootstrappedSession;
@property (nonatomic, assign) BOOL isMiniMode;
@property (nonatomic, assign) BOOL isRestModeEnabled;
@property (nonatomic, assign) BOOL isResting;
@property (nonatomic, assign) NSInteger lastRestSuccessCount;
@property (nonatomic, strong) UILabel *riskControlLabel;
@property (nonatomic, assign) BOOL isRiskControlled;
@property (nonatomic, assign) NSInteger consecutivePDPFailures;
@property (nonatomic, assign) NSInteger apiType;
@property (nonatomic, assign) CGPoint panelOrigin;
@property (nonatomic, assign) CGPoint bubbleOrigin;
@property (nonatomic, assign) CGPoint miniOrigin;
@property (nonatomic, assign) CGSize panelSize;
+ (instancetype)shared;
- (void)start;
- (void)installCaptureHooksIfNeeded;
- (void)installShopeeSpecificHooksIfNeeded;
- (void)scheduleNextTaskCycleWithReason:(NSString *)reason immediate:(BOOL)immediate;
- (void)startHeartbeatWithCompletion:(void (^)(BOOL allowed))completion;
- (void)inspectCapturedData:(NSData *)data sourceURLString:(NSString *)urlString;
- (void)inspectResponseData:(NSData *)data response:(NSURLResponse *)response request:(NSURLRequest *)request error:(NSError *)error;
- (void)inspectParsedJSONObject:(id)object rawData:(NSData *)rawData;
- (BOOL)handleNoDataCaptureWithMessage:(NSString *)message currentItemID:(NSString *)currentItemID;
- (void)handleRiskControlDetectedWithMessage:(NSString *)message;
@end

@implementation SHPPluginController

+ (instancetype)shared {
    static SHPPluginController *controller;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        controller = [SHPPluginController new];
    });
    return controller;
}

- (instancetype)init {
    self = [super init];
    if (!self) {
        return nil;
    }

    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    configuration.timeoutIntervalForRequest = 15.0;
    configuration.timeoutIntervalForResource = 20.0;
    configuration.HTTPMaximumConnectionsPerHost = 2;
    configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    self.session = [NSURLSession sessionWithConfiguration:configuration];

    [self loadDefaults];
    return self;
}

- (void)start {
    NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
    [center addObserver:self selector:@selector(applicationDidBecomeActive:) name:UIApplicationDidBecomeActiveNotification object:nil];
    [center addObserver:self selector:@selector(applicationWillResignActive:) name:UIApplicationWillResignActiveNotification object:nil];

    if (!self.hasBootstrappedSession) {
        self.hasBootstrappedSession = YES;
        if (self.currentTask || self.isRunning) {
            self.currentTask = nil;
            self.isRunning = NO;
            [self clearPendingSubmissionState];
            [self persistDefaults];
        }
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if ([UIApplication sharedApplication].applicationState == UIApplicationStateActive) {
            [self applicationDidBecomeActive:nil];
        }
    });
}

- (void)loadDefaults {
    self.token = SHPStringValue(SHPPreferencesCopyValue(kSHPDefaultsTokenKey));
    self.groupID = SHPStringValue(SHPPreferencesCopyValue(kSHPDefaultsGroupIDKey));
    self.apiType = [SHPPreferencesCopyValue(kSHPDefaultsApiTypeKey) integerValue];
    if (self.apiType != 2) {
        self.apiType = 1;
    }
    self.deviceID = SHPStringValue(SHPPreferencesCopyValue(kSHPDefaultsDeviceIDKey));
    if (!self.deviceID.length) {
        self.deviceID = NSUUID.UUID.UUIDString;
        SHPPreferencesSetValue(kSHPDefaultsDeviceIDKey, self.deviceID);
        SHPPreferencesSynchronize();
    }
    self.isRunning = [SHPPreferencesCopyValue(kSHPDefaultsRunningKey) boolValue];
    self.isCollapsed = [SHPPreferencesCopyValue(kSHPDefaultsCollapsedKey) boolValue];
    self.successCount = [SHPPreferencesCopyValue(kSHPDefaultsSuccessCountKey) integerValue];
    self.isMiniMode = [SHPPreferencesCopyValue(kSHPDefaultsMiniModeKey) boolValue];
    self.isRestModeEnabled = [SHPPreferencesCopyValue(kSHPDefaultsRestEnabledKey) boolValue];
    self.lastRestSuccessCount = [SHPPreferencesCopyValue(kSHPDefaultsLastRestSuccessCountKey) integerValue];
    self.currentTask = [SHPTask taskFromDictionary:SHPPreferencesCopyValue(kSHPDefaultsCurrentTaskKey)];
    CGFloat savedWidth = [SHPPreferencesCopyValue(kSHPDefaultsPanelWidthKey) doubleValue];
    CGFloat savedHeight = [SHPPreferencesCopyValue(kSHPDefaultsPanelHeightKey) doubleValue];
    self.panelSize = CGSizeMake(savedWidth > 0.0 ? savedWidth : 312.0, savedHeight > 0.0 ? savedHeight : 424.0);
}

- (void)persistDefaults {
    SHPPreferencesSetValue(kSHPDefaultsRunningKey, @(self.isRunning));
    SHPPreferencesSetValue(kSHPDefaultsCollapsedKey, @(self.isCollapsed));
    SHPPreferencesSetValue(kSHPDefaultsMiniModeKey, @(self.isMiniMode));
    SHPPreferencesSetValue(kSHPDefaultsRestEnabledKey, @(self.isRestModeEnabled));
    SHPPreferencesSetValue(kSHPDefaultsLastRestSuccessCountKey, @(self.lastRestSuccessCount));
    SHPPreferencesSetValue(kSHPDefaultsSuccessCountKey, @(self.successCount));
    SHPPreferencesSetValue(kSHPDefaultsPanelWidthKey, @(self.panelSize.width));
    SHPPreferencesSetValue(kSHPDefaultsPanelHeightKey, @(self.panelSize.height));
    if (self.intervalField.text.length) {
        SHPPreferencesSetValue(kSHPDefaultsIntervalRangeKey, self.intervalField.text);
    }
    if (self.restCountField.text.length) {
        SHPPreferencesSetValue(kSHPDefaultsRestCountKey, self.restCountField.text);
    }
    if (self.restMinutesField.text.length) {
        SHPPreferencesSetValue(kSHPDefaultsRestMinutesKey, self.restMinutesField.text);
    }
    if (self.token.length) {
        SHPPreferencesSetValue(kSHPDefaultsTokenKey, self.token);
    } else {
        SHPPreferencesSetValue(kSHPDefaultsTokenKey, nil);
    }
    if (self.groupID.length) {
        SHPPreferencesSetValue(kSHPDefaultsGroupIDKey, self.groupID);
    } else {
        SHPPreferencesSetValue(kSHPDefaultsGroupIDKey, nil);
    }
    SHPPreferencesSetValue(kSHPDefaultsApiTypeKey, @(self.apiType > 0 ? self.apiType : 1));
    if (self.deviceID.length) {
        SHPPreferencesSetValue(kSHPDefaultsDeviceIDKey, self.deviceID);
    }

    if (self.currentTask) {
        SHPPreferencesSetValue(kSHPDefaultsCurrentTaskKey, self.currentTask.dictionaryRepresentation);
    } else {
        SHPPreferencesSetValue(kSHPDefaultsCurrentTaskKey, nil);
    }
    SHPPreferencesSynchronize();
}

- (void)saveCredentials {
    if (self.usernameField.text.length) {
        SHPPreferencesSetValue(kSHPDefaultsUsernameKey, self.usernameField.text);
    } else {
        SHPPreferencesSetValue(kSHPDefaultsUsernameKey, nil);
    }

    if (self.passwordField.text.length) {
        SHPPreferencesSetValue(kSHPDefaultsPasswordKey, self.passwordField.text);
    } else {
        SHPPreferencesSetValue(kSHPDefaultsPasswordKey, nil);
    }
    SHPPreferencesSynchronize();
}

- (NSString *)savedUsername {
    return SHPStringValue(SHPPreferencesCopyValue(kSHPDefaultsUsernameKey));
}

- (NSString *)savedPassword {
    return SHPStringValue(SHPPreferencesCopyValue(kSHPDefaultsPasswordKey));
}

- (NSString *)savedIntervalRange {
    NSString *saved = SHPStringValue(SHPPreferencesCopyValue(kSHPDefaultsIntervalRangeKey));
    return saved.length ? saved : @"1-8";
}

- (NSString *)savedRestCount {
    NSString *saved = SHPStringValue(SHPPreferencesCopyValue(kSHPDefaultsRestCountKey));
    return saved.length ? saved : @"40";
}

- (NSString *)savedRestMinutes {
    NSString *saved = SHPStringValue(SHPPreferencesCopyValue(kSHPDefaultsRestMinutesKey));
    return saved.length ? saved : @"10";
}

- (NSInteger)currentRestCountThreshold {
    NSString *rawValue = SHPStringValue(self.restCountField.text);
    if (!rawValue.length) {
        rawValue = [self savedRestCount];
    }
    NSInteger value = [rawValue integerValue];
    return MAX(1, MIN(value, 9999));
}

- (NSTimeInterval)currentRestDuration {
    NSString *rawValue = SHPStringValue(self.restMinutesField.text);
    if (!rawValue.length) {
        rawValue = [self savedRestMinutes];
    }
    double minutes = [rawValue doubleValue];
    minutes = MAX(1.0, MIN(minutes, 1440.0));
    return minutes * 60.0;
}

- (NSArray<NSNumber *> *)currentIntervalBounds {
    NSString *raw = SHPStringValue(self.intervalField.text) ?: [self savedIntervalRange];
    NSString *normalized = [[[raw lowercaseString] stringByReplacingOccurrencesOfString:@"秒" withString:@""]
        stringByReplacingOccurrencesOfString:@"s" withString:@""];
    normalized = [[normalized stringByReplacingOccurrencesOfString:@"~" withString:@"-"]
        stringByReplacingOccurrencesOfString:@"—" withString:@"-"];
    normalized = [[normalized stringByReplacingOccurrencesOfString:@"－" withString:@"-"]
        stringByReplacingOccurrencesOfString:@" " withString:@""];

    NSInteger minValue = 1;
    NSInteger maxValue = 8;
    NSArray<NSString *> *parts = [normalized componentsSeparatedByString:@"-"];
    if (parts.count >= 2) {
        NSInteger first = [parts[0] integerValue];
        NSInteger second = [parts[1] integerValue];
        if (first > 0) {
            minValue = first;
        }
        if (second > 0) {
            maxValue = second;
        }
    } else if (normalized.length) {
        NSInteger single = [normalized integerValue];
        if (single > 0) {
            minValue = single;
            maxValue = single;
        }
    }

    minValue = MAX(1, MIN(minValue, 60));
    maxValue = MAX(1, MIN(maxValue, 60));
    if (minValue > maxValue) {
        NSInteger temp = minValue;
        minValue = maxValue;
        maxValue = temp;
    }

    return @[@(minValue), @(maxValue)];
}

- (NSTimeInterval)randomTaskDelay {
    NSArray<NSNumber *> *bounds = [self currentIntervalBounds];
    NSInteger minValue = bounds[0].integerValue;
    NSInteger maxValue = bounds[1].integerValue;
    if (minValue >= maxValue) {
        return (NSTimeInterval)minValue;
    }
    uint32_t span = (uint32_t)(maxValue - minValue + 1);
    return (NSTimeInterval)(minValue + arc4random_uniform(span));
}

- (UIWindowScene *)activeWindowScene {
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) {
                continue;
            }
            if (scene.activationState == UISceneActivationStateForegroundActive || scene.activationState == UISceneActivationStateForegroundInactive) {
                return (UIWindowScene *)scene;
            }
        }
    }
    return nil;
}

- (void)ensureOverlay {
    if (self.overlayWindow) {
        self.overlayWindow.hidden = NO;
        return;
    }

    CGRect screenBounds = UIScreen.mainScreen.bounds;
    UIViewController *rootController = [UIViewController new];
    rootController.view.backgroundColor = UIColor.clearColor;

    if (@available(iOS 13.0, *)) {
        UIWindowScene *scene = [self activeWindowScene];
        if (!scene) {
            return;
        }
        self.overlayWindow = [[SHPPassthroughWindow alloc] initWithWindowScene:scene];
    } else {
        self.overlayWindow = [[SHPPassthroughWindow alloc] initWithFrame:screenBounds];
    }

    self.overlayWindow.frame = screenBounds;
    self.overlayWindow.backgroundColor = UIColor.clearColor;
    self.overlayWindow.windowLevel = UIWindowLevelAlert + 20.0;
    self.overlayWindow.rootViewController = rootController;
    self.overlayWindow.hidden = NO;

    [self buildInterfaceInView:rootController.view];
    [self layoutInterface];
}

- (void)buildInterfaceInView:(UIView *)containerView {
    self.panelView = [[UIView alloc] initWithFrame:CGRectZero];
    self.panelView.backgroundColor = [UIColor colorWithRed:0.07 green:0.10 blue:0.16 alpha:0.94];
    self.panelView.layer.cornerRadius = 18.0;
    self.panelView.layer.borderWidth = 1.0;
    self.panelView.layer.borderColor = [UIColor colorWithRed:0.26 green:0.74 blue:0.73 alpha:1.0].CGColor;
    self.panelView.clipsToBounds = YES;
    [containerView addSubview:self.panelView];

    self.headerView = [[UIView alloc] initWithFrame:CGRectZero];
    self.headerView.backgroundColor = [UIColor colorWithRed:0.10 green:0.16 blue:0.25 alpha:0.98];
    [self.panelView addSubview:self.headerView];

    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    titleLabel.text = @"格界";
    titleLabel.textColor = [UIColor colorWithRed:0.92 green:0.98 blue:0.98 alpha:1.0];
    titleLabel.font = [UIFont boldSystemFontOfSize:16.0];
    [self.headerView addSubview:titleLabel];

    self.collapseButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.collapseButton setTitle:@"隐藏" forState:UIControlStateNormal];
    [self.collapseButton setTitleColor:[UIColor colorWithRed:0.55 green:0.90 blue:0.86 alpha:1.0] forState:UIControlStateNormal];
    self.collapseButton.titleLabel.font = [UIFont boldSystemFontOfSize:13.0];
    [self.collapseButton addTarget:self action:@selector(toggleCollapsed) forControlEvents:UIControlEventTouchUpInside];
    [self.headerView addSubview:self.collapseButton];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.statusLabel.textColor = [UIColor colorWithRed:0.89 green:0.94 blue:0.96 alpha:1.0];
    self.statusLabel.font = [UIFont systemFontOfSize:12.0 weight:UIFontWeightSemibold];
    [self.panelView addSubview:self.statusLabel];

    self.taskLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.taskLabel.textColor = [UIColor colorWithRed:0.65 green:0.76 blue:0.84 alpha:1.0];
    self.taskLabel.font = [UIFont systemFontOfSize:11.0];
    self.taskLabel.numberOfLines = 2;
    [self.panelView addSubview:self.taskLabel];

    self.counterLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.counterLabel.textColor = [UIColor colorWithRed:0.88 green:0.83 blue:0.58 alpha:1.0];
    self.counterLabel.font = [UIFont systemFontOfSize:11.0 weight:UIFontWeightSemibold];
    [self.panelView addSubview:self.counterLabel];

    self.usernameField = [self makeTextFieldWithPlaceholder:@"用户名"];
    self.usernameField.text = [self savedUsername];
    self.usernameField.delegate = self;
    [self.panelView addSubview:self.usernameField];

    self.passwordField = [self makeTextFieldWithPlaceholder:@"密码"];
    self.passwordField.secureTextEntry = YES;
    self.passwordField.text = [self savedPassword];
    self.passwordField.delegate = self;
    self.passwordField.returnKeyType = UIReturnKeyDone;
    self.passwordField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.passwordField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.passwordField.clearButtonMode = UITextFieldViewModeNever;
    [self installPasswordVisibilityButton];
    [self setPasswordVisible:NO];
    [self.panelView addSubview:self.passwordField];

    self.intervalField = [self makeTextFieldWithPlaceholder:@"间隔 1-8 秒"];
    self.intervalField.text = [self savedIntervalRange];
    self.intervalField.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
    [self.intervalField addTarget:self action:@selector(intervalFieldChanged:) forControlEvents:UIControlEventEditingChanged];
    [self.panelView addSubview:self.intervalField];

    self.startTaskButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.startTaskButton.backgroundColor = [UIColor colorWithRed:0.19 green:0.44 blue:0.78 alpha:1.0];
    [self.startTaskButton setTitle:@"启动任务" forState:UIControlStateNormal];
    [self.startTaskButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    self.startTaskButton.titleLabel.font = [UIFont boldSystemFontOfSize:15.0];
    self.startTaskButton.titleLabel.numberOfLines = 2;
    self.startTaskButton.titleLabel.textAlignment = NSTextAlignmentCenter;
    self.startTaskButton.layer.cornerRadius = 12.0;
    [self.startTaskButton addTarget:self action:@selector(startTaskButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.panelView addSubview:self.startTaskButton];

    self.resetCountButton = [self makeButtonWithTitle:@"重置计数" color:[UIColor colorWithRed:0.37 green:0.39 blue:0.45 alpha:1.0]];
    [self.resetCountButton addTarget:self action:@selector(resetCountButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.panelView addSubview:self.resetCountButton];

    self.miniModeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.miniModeButton.backgroundColor = [UIColor colorWithRed:0.14 green:0.18 blue:0.26 alpha:1.0];
    self.miniModeButton.titleLabel.font = [UIFont systemFontOfSize:13.0];
    self.miniModeButton.layer.cornerRadius = 10.0;
    self.miniModeButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    self.miniModeButton.contentEdgeInsets = UIEdgeInsetsMake(0.0, 10.0, 0.0, 0.0);
    [self.miniModeButton addTarget:self action:@selector(toggleMiniMode) forControlEvents:UIControlEventTouchUpInside];
    [self.panelView addSubview:self.miniModeButton];

    self.restModeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.restModeButton.backgroundColor = [UIColor colorWithRed:0.14 green:0.18 blue:0.26 alpha:1.0];
    self.restModeButton.titleLabel.font = [UIFont systemFontOfSize:12.0];
    self.restModeButton.layer.cornerRadius = 10.0;
    self.restModeButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    self.restModeButton.contentEdgeInsets = UIEdgeInsetsMake(0.0, 8.0, 0.0, 0.0);
    [self.restModeButton addTarget:self action:@selector(toggleRestMode) forControlEvents:UIControlEventTouchUpInside];
    [self.panelView addSubview:self.restModeButton];

    self.restCountField = [self makeTextFieldWithPlaceholder:@"N"];
    self.restCountField.text = [self savedRestCount];
    self.restCountField.keyboardType = UIKeyboardTypeNumberPad;
    [self.restCountField addTarget:self action:@selector(restSettingFieldChanged:) forControlEvents:UIControlEventEditingChanged];
    [self.panelView addSubview:self.restCountField];

    self.restMinutesField = [self makeTextFieldWithPlaceholder:@"min"];
    self.restMinutesField.text = [self savedRestMinutes];
    self.restMinutesField.keyboardType = UIKeyboardTypeDecimalPad;
    [self.restMinutesField addTarget:self action:@selector(restSettingFieldChanged:) forControlEvents:UIControlEventEditingChanged];
    [self.panelView addSubview:self.restMinutesField];

    self.logView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.logView.backgroundColor = [UIColor colorWithRed:0.04 green:0.06 blue:0.10 alpha:0.95];
    self.logView.textColor = [UIColor colorWithRed:0.75 green:0.87 blue:0.89 alpha:1.0];
    self.logView.font = [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular];
    self.logView.editable = NO;
    self.logView.selectable = YES;
    self.logView.layer.cornerRadius = 12.0;
    [self.panelView addSubview:self.logView];

    self.bubbleButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.bubbleButton setTitle:@"格界" forState:UIControlStateNormal];
    [self.bubbleButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    self.bubbleButton.titleLabel.font = [UIFont boldSystemFontOfSize:13.0];
    self.bubbleButton.backgroundColor = [UIColor colorWithRed:0.15 green:0.58 blue:0.63 alpha:0.94];
    self.bubbleButton.layer.cornerRadius = 28.0;
    self.bubbleButton.layer.borderWidth = 2.0;
    self.bubbleButton.layer.borderColor = [UIColor colorWithRed:0.80 green:0.98 blue:0.96 alpha:1.0].CGColor;
    [self.bubbleButton addTarget:self action:@selector(toggleCollapsed) forControlEvents:UIControlEventTouchUpInside];
    [containerView addSubview:self.bubbleButton];

    self.miniView = [[UIView alloc] initWithFrame:CGRectZero];
    self.miniView.backgroundColor = [UIColor colorWithRed:0.05 green:0.08 blue:0.14 alpha:0.75];
    self.miniView.layer.cornerRadius = 12.0;
    self.miniView.layer.borderWidth = 1.0;
    self.miniView.layer.borderColor = [UIColor colorWithRed:0.26 green:0.74 blue:0.73 alpha:0.5].CGColor;
    [containerView addSubview:self.miniView];

    self.miniInfoLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.miniInfoLabel.textColor = [UIColor colorWithRed:0.85 green:0.94 blue:0.92 alpha:1.0];
    self.miniInfoLabel.font = [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightMedium];
    self.miniInfoLabel.numberOfLines = 3;
    [self.miniView addSubview:self.miniInfoLabel];

    UIPanGestureRecognizer *miniPan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handleMiniPan:)];
    [self.miniView addGestureRecognizer:miniPan];

    UITapGestureRecognizer *miniTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(miniViewTapped)];
    [self.miniView addGestureRecognizer:miniTap];

    self.riskControlLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.riskControlLabel.text = @"此账号已风控！";
    self.riskControlLabel.textColor = [UIColor whiteColor];
    self.riskControlLabel.backgroundColor = [UIColor colorWithRed:0.90 green:0.30 blue:0.25 alpha:0.92];
    self.riskControlLabel.font = [UIFont boldSystemFontOfSize:15.0];
    self.riskControlLabel.textAlignment = NSTextAlignmentCenter;
    self.riskControlLabel.layer.cornerRadius = 10.0;
    self.riskControlLabel.clipsToBounds = YES;
    self.riskControlLabel.hidden = YES;
    [containerView addSubview:self.riskControlLabel];

    UIPanGestureRecognizer *panelPan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePanelPan:)];
    [self.headerView addGestureRecognizer:panelPan];

    UIPanGestureRecognizer *bubblePan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handleBubblePan:)];
    [self.bubbleButton addGestureRecognizer:bubblePan];

    self.resizeHandle = [[UIView alloc] initWithFrame:CGRectZero];
    self.resizeHandle.backgroundColor = [UIColor colorWithRed:0.34 green:0.85 blue:0.82 alpha:0.95];
    self.resizeHandle.layer.cornerRadius = 7.0;
    [self.panelView addSubview:self.resizeHandle];

    UIPanGestureRecognizer *resizePan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handleResizePan:)];
    [self.resizeHandle addGestureRecognizer:resizePan];
}

- (UITextField *)makeTextFieldWithPlaceholder:(NSString *)placeholder {
    UITextField *field = [[UITextField alloc] initWithFrame:CGRectZero];
    field.backgroundColor = [UIColor colorWithRed:0.11 green:0.14 blue:0.20 alpha:1.0];
    field.textColor = [UIColor colorWithRed:0.95 green:0.97 blue:0.98 alpha:1.0];
    field.tintColor = [UIColor colorWithRed:0.46 green:0.89 blue:0.86 alpha:1.0];
    field.font = [UIFont systemFontOfSize:13.0];
    field.attributedPlaceholder = [[NSAttributedString alloc] initWithString:placeholder attributes:@{
        NSForegroundColorAttributeName: [UIColor colorWithRed:0.48 green:0.58 blue:0.67 alpha:1.0]
    }];
    field.borderStyle = UITextBorderStyleNone;
    field.leftView = [[UIView alloc] initWithFrame:CGRectMake(0.0, 0.0, 10.0, 10.0)];
    field.leftViewMode = UITextFieldViewModeAlways;
    field.layer.cornerRadius = 10.0;
    return field;
}

- (void)installPasswordVisibilityButton {
    self.passwordVisibilityButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.passwordVisibilityButton.frame = CGRectMake(0.0, 0.0, 44.0, 36.0);
    self.passwordVisibilityButton.tintColor = [UIColor colorWithRed:0.55 green:0.90 blue:0.86 alpha:1.0];
    self.passwordVisibilityButton.titleLabel.font = [UIFont boldSystemFontOfSize:11.0];
    [self.passwordVisibilityButton addTarget:self action:@selector(togglePasswordVisibility) forControlEvents:UIControlEventTouchUpInside];
    self.passwordField.rightView = self.passwordVisibilityButton;
    self.passwordField.rightViewMode = UITextFieldViewModeAlways;
    [self updatePasswordVisibilityButton];
}

- (void)setPasswordVisible:(BOOL)visible {
    if (!self.passwordField) {
        return;
    }

    NSString *password = self.passwordField.text ?: @"";
    UITextRange *selectedRange = self.passwordField.selectedTextRange;
    self.passwordField.secureTextEntry = !visible;
    self.passwordField.text = password;
    if (selectedRange) {
        self.passwordField.selectedTextRange = selectedRange;
    }
    [self updatePasswordVisibilityButton];
}

- (void)togglePasswordVisibility {
    [self setPasswordVisible:self.passwordField.secureTextEntry];
}

- (void)updatePasswordVisibilityButton {
    BOOL visible = self.passwordField && !self.passwordField.secureTextEntry;
    [self.passwordVisibilityButton setImage:nil forState:UIControlStateNormal];
    [self.passwordVisibilityButton setTitle:(visible ? @"Hide" : @"Show") forState:UIControlStateNormal];
    self.passwordVisibilityButton.accessibilityLabel = visible ? @"Hide password" : @"Show password";
}

- (UIButton *)makeButtonWithTitle:(NSString *)title color:(UIColor *)color {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.backgroundColor = color;
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:13.0];
    button.layer.cornerRadius = 10.0;
    return button;
}

- (void)layoutInterface {
    if (!self.overlayWindow || !self.panelView) {
        return;
    }

    CGRect bounds = self.overlayWindow.bounds;
    self.overlayWindow.frame = bounds;

    CGSize panelSize = self.panelSize;
    panelSize.width = MIN(MAX(280.0, panelSize.width), MAX(280.0, CGRectGetWidth(bounds) - 12.0));
    panelSize.height = MIN(MAX(390.0, panelSize.height), MAX(390.0, CGRectGetHeight(bounds) - 24.0));
    self.panelSize = panelSize;
    if (CGPointEqualToPoint(self.panelOrigin, CGPointZero)) {
        self.panelOrigin = CGPointMake(18.0, MAX(96.0, CGRectGetMidY(bounds) - panelSize.height * 0.35));
    }

    CGFloat maxPanelX = MAX(8.0, CGRectGetWidth(bounds) - panelSize.width - 8.0);
    CGFloat maxPanelY = MAX(40.0, CGRectGetHeight(bounds) - panelSize.height - 20.0);
    self.panelOrigin = CGPointMake(MIN(MAX(8.0, self.panelOrigin.x), maxPanelX), MIN(MAX(48.0, self.panelOrigin.y), maxPanelY));
    self.panelView.frame = CGRectMake(self.panelOrigin.x, self.panelOrigin.y, panelSize.width, panelSize.height);

    CGFloat padding = 14.0;
    self.headerView.frame = CGRectMake(0.0, 0.0, panelSize.width, 42.0);
    UILabel *titleLabel = self.headerView.subviews.firstObject;
    titleLabel.frame = CGRectMake(padding, 0.0, 160.0, 42.0);
    self.collapseButton.frame = CGRectMake(panelSize.width - 64.0, 0.0, 56.0, 42.0);

    self.statusLabel.frame = CGRectMake(padding, 52.0, panelSize.width - padding * 2.0, 18.0);
    self.taskLabel.frame = CGRectMake(padding, 72.0, panelSize.width - padding * 2.0, 28.0);
    self.counterLabel.frame = CGRectMake(padding, 102.0, panelSize.width - padding * 2.0, 18.0);

    CGFloat squareSize = 90.0;
    CGFloat fieldWidth = panelSize.width - padding * 3.0 - squareSize;
    self.usernameField.frame = CGRectMake(padding, 128.0, fieldWidth, 36.0);
    self.passwordField.frame = CGRectMake(padding, 172.0, fieldWidth, 36.0);
    self.startTaskButton.frame = CGRectMake(CGRectGetMaxX(self.usernameField.frame) + padding, 128.0, squareSize, squareSize);
    self.intervalField.frame = CGRectMake(padding, 220.0, panelSize.width - padding * 2.0, 36.0);
    self.resetCountButton.frame = CGRectMake(padding, 264.0, (panelSize.width - padding * 3.0) * 0.5, 36.0);
    self.miniModeButton.frame = CGRectMake(CGRectGetMaxX(self.resetCountButton.frame) + padding, 264.0, panelSize.width - CGRectGetMaxX(self.resetCountButton.frame) - padding * 2.0, 36.0);
    CGFloat restY = 308.0;
    CGFloat restGap = 8.0;
    CGFloat restButtonWidth = MAX(92.0, panelSize.width - padding * 2.0 - restGap * 2.0 - 116.0);
    self.restModeButton.frame = CGRectMake(padding, restY, restButtonWidth, 34.0);
    self.restCountField.frame = CGRectMake(CGRectGetMaxX(self.restModeButton.frame) + restGap, restY, 54.0, 34.0);
    self.restMinutesField.frame = CGRectMake(CGRectGetMaxX(self.restCountField.frame) + restGap, restY, 54.0, 34.0);
    CGFloat logY = 354.0;
    CGFloat logHeight = MAX(54.0, panelSize.height - logY - 16.0);
    self.logView.frame = CGRectMake(padding, logY, panelSize.width - padding * 2.0, logHeight);
    self.resizeHandle.frame = CGRectMake(panelSize.width - 18.0, panelSize.height - 18.0, 12.0, 12.0);

    if (CGPointEqualToPoint(self.bubbleOrigin, CGPointZero)) {
        self.bubbleOrigin = CGPointMake(CGRectGetWidth(bounds) - 72.0, CGRectGetMidY(bounds));
    }

    CGFloat bubbleSize = 56.0;
    CGFloat maxBubbleX = MAX(8.0, CGRectGetWidth(bounds) - bubbleSize - 8.0);
    CGFloat maxBubbleY = MAX(40.0, CGRectGetHeight(bounds) - bubbleSize - 18.0);
    self.bubbleOrigin = CGPointMake(MIN(MAX(8.0, self.bubbleOrigin.x), maxBubbleX), MIN(MAX(40.0, self.bubbleOrigin.y), maxBubbleY));
    self.bubbleButton.frame = CGRectMake(self.bubbleOrigin.x, self.bubbleOrigin.y, bubbleSize, bubbleSize);

    CGFloat miniWidth = 155.0;
    CGFloat miniHeight = 52.0;
    if (CGPointEqualToPoint(self.miniOrigin, CGPointZero)) {
        self.miniOrigin = CGPointMake(CGRectGetWidth(bounds) - miniWidth - 12.0, 60.0);
    }
    CGFloat maxMiniX = MAX(4.0, CGRectGetWidth(bounds) - miniWidth - 4.0);
    CGFloat maxMiniY = MAX(40.0, CGRectGetHeight(bounds) - miniHeight - 18.0);
    self.miniOrigin = CGPointMake(MIN(MAX(4.0, self.miniOrigin.x), maxMiniX), MIN(MAX(40.0, self.miniOrigin.y), maxMiniY));
    self.miniView.frame = CGRectMake(self.miniOrigin.x, self.miniOrigin.y, miniWidth, miniHeight);
    self.miniInfoLabel.frame = CGRectMake(8.0, 4.0, miniWidth - 16.0, miniHeight - 8.0);

    CGFloat riskLabelWidth = CGRectGetWidth(bounds) - 60.0;
    CGFloat riskLabelHeight = 44.0;
    self.riskControlLabel.frame = CGRectMake(
        (CGRectGetWidth(bounds) - riskLabelWidth) / 2.0,
        CGRectGetHeight(bounds) - riskLabelHeight - 34.0,
        riskLabelWidth,
        riskLabelHeight
    );
    self.riskControlLabel.hidden = !self.isRiskControlled;

    BOOL showMini = self.isCollapsed && self.isMiniMode;
    self.panelView.hidden = self.isCollapsed;
    self.bubbleButton.hidden = !self.isCollapsed || showMini;
    self.miniView.hidden = !showMini;
}

- (void)refreshUI {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self layoutInterface];

        NSString *modeText = self.isRunning ? @"运行中" : @"已暂停";
        NSString *tokenText = self.token.length ? @"已登录" : @"未登录";
        self.statusLabel.text = [NSString stringWithFormat:@"状态: %@ | %@", tokenText, modeText];

        if (self.currentTask.itemID.length && self.currentTask.shopID.length) {
            self.taskLabel.text = [NSString stringWithFormat:@"当前任务: shop=%@  item=%@", self.currentTask.shopID, self.currentTask.itemID];
        } else if (self.currentTask.traceID.length) {
            self.taskLabel.text = [NSString stringWithFormat:@"当前任务: %@", self.currentTask.traceID];
        } else {
            self.taskLabel.text = @"当前任务: 暂无";
        }

        self.counterLabel.text = [NSString stringWithFormat:@"本地成功上传: %ld", (long)self.successCount];
        [self.startTaskButton setTitle:(self.isRunning ? @"停止任务" : @"启动任务") forState:UIControlStateNormal];
        self.startTaskButton.backgroundColor = self.isRunning ? [UIColor colorWithRed:0.80 green:0.34 blue:0.22 alpha:1.0] : [UIColor colorWithRed:0.19 green:0.44 blue:0.78 alpha:1.0];

        NSString *miniTitle = self.isMiniMode ? @"☑ 小窗模式" : @"☐ 小窗模式";
        [self.miniModeButton setTitle:miniTitle forState:UIControlStateNormal];
        [self.miniModeButton setTitleColor:(self.isMiniMode ? [UIColor colorWithRed:0.46 green:0.89 blue:0.86 alpha:1.0] : [UIColor colorWithRed:0.55 green:0.62 blue:0.70 alpha:1.0]) forState:UIControlStateNormal];

        if (self.isResting) {
            if (self.nextFireDate) {
                NSTimeInterval remaining = MAX(0.0, [self.nextFireDate timeIntervalSinceNow]);
                NSInteger minutes = (NSInteger)(remaining / 60.0);
                NSInteger seconds = (NSInteger)remaining % 60;
                self.counterLabel.text = [NSString stringWithFormat:@"本地成功上传: %ld | 休息 %02ld:%02ld", (long)self.successCount, (long)minutes, (long)seconds];
            }
            [self.startTaskButton setTitle:@"休息中" forState:UIControlStateNormal];
            self.startTaskButton.backgroundColor = [UIColor colorWithRed:0.34 green:0.39 blue:0.47 alpha:1.0];
        }

        NSString *restTitle = self.isRestModeEnabled ? @"休息开" : @"休息关";
        [self.restModeButton setTitle:restTitle forState:UIControlStateNormal];
        [self.restModeButton setTitleColor:(self.isRestModeEnabled ? [UIColor colorWithRed:0.46 green:0.89 blue:0.86 alpha:1.0] : [UIColor colorWithRed:0.55 green:0.62 blue:0.70 alpha:1.0]) forState:UIControlStateNormal];

        [self updateMiniViewContent];
    });
}

- (void)appendLog:(NSString *)message {
    if (!message.length) {
        return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.dateFormat = @"HH:mm:ss";
        NSString *timestamp = [formatter stringFromDate:[NSDate date]];
        NSString *line = [NSString stringWithFormat:@"[%@] %@\n", timestamp, message];
        NSString *existing = self.logView.text ?: @"";
        NSString *combined = [existing stringByAppendingString:line];

        NSArray<NSString *> *lines = [combined componentsSeparatedByString:@"\n"];
        if (lines.count > 80) {
            NSRange keepRange = NSMakeRange(MAX((NSInteger)lines.count - 81, 0), MIN((NSInteger)80, (NSInteger)lines.count - 1));
            NSArray<NSString *> *tail = [lines subarrayWithRange:keepRange];
            combined = [[tail componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
        }

        self.logView.text = combined;
        NSRange bottom = NSMakeRange(self.logView.text.length, 0);
        [self.logView scrollRangeToVisible:bottom];
    });
}

- (void)applicationDidBecomeActive:(NSNotification *)note {
    (void)note;
    [self ensureOverlay];
    [self refreshUI];
}

- (void)applicationWillResignActive:(NSNotification *)note {
    (void)note;
    [self persistDefaults];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    if (textField == self.passwordField) {
        [textField resignFirstResponder];
        [self saveCredentials];
        return NO;
    }
    if (textField == self.restCountField || textField == self.restMinutesField) {
        [textField resignFirstResponder];
        [self restSettingFieldChanged:textField];
        return NO;
    }
    if (textField == self.intervalField) {
        [textField resignFirstResponder];
        [self intervalFieldChanged:textField];
        return NO;
    }
    [textField resignFirstResponder];
    return YES;
}

- (void)toggleCollapsed {
    self.isCollapsed = !self.isCollapsed;
    [self persistDefaults];
    [self refreshUI];
}

- (void)handlePanelPan:(UIPanGestureRecognizer *)gesture {
    CGPoint translation = [gesture translationInView:self.overlayWindow.rootViewController.view];
    if (gesture.state == UIGestureRecognizerStateChanged || gesture.state == UIGestureRecognizerStateEnded) {
        CGPoint origin = self.panelOrigin;
        origin.x += translation.x;
        origin.y += translation.y;
        self.panelOrigin = origin;
        [gesture setTranslation:CGPointZero inView:self.overlayWindow.rootViewController.view];
        [self layoutInterface];
    }
}

- (void)handleBubblePan:(UIPanGestureRecognizer *)gesture {
    CGPoint translation = [gesture translationInView:self.overlayWindow.rootViewController.view];
    if (gesture.state == UIGestureRecognizerStateChanged || gesture.state == UIGestureRecognizerStateEnded) {
        CGPoint origin = self.bubbleOrigin;
        origin.x += translation.x;
        origin.y += translation.y;
        self.bubbleOrigin = origin;
        [gesture setTranslation:CGPointZero inView:self.overlayWindow.rootViewController.view];
        [self layoutInterface];
    }
}

- (void)handleResizePan:(UIPanGestureRecognizer *)gesture {
    CGPoint translation = [gesture translationInView:self.overlayWindow.rootViewController.view];
    if (gesture.state == UIGestureRecognizerStateChanged || gesture.state == UIGestureRecognizerStateEnded) {
        CGSize size = self.panelSize;
        size.width += translation.x;
        size.height += translation.y;
        self.panelSize = size;
        [gesture setTranslation:CGPointZero inView:self.overlayWindow.rootViewController.view];
        [self layoutInterface];
        if (gesture.state == UIGestureRecognizerStateEnded) {
            [self persistDefaults];
        }
    }
}

- (void)intervalFieldChanged:(UITextField *)textField {
    (void)textField;
    [self persistDefaults];
}

- (void)restSettingFieldChanged:(UITextField *)textField {
    (void)textField;
    [self persistDefaults];
}

- (void)startTaskButtonTapped {
    [self saveCredentials];
    self.isRunning = !self.isRunning;
    [self persistDefaults];
    [self refreshUI];

    if (self.isRunning) {
        self.isRiskControlled = NO;
        self.isResting = NO;
        self.consecutivePDPFailures = 0;
        self.token = nil;
        [self persistDefaults];
        [self appendLog:@"已启动,重新登录"];
        [self loginWithCompletion:^(BOOL success) {
            if (success) {
                [self startHeartbeatWithCompletion:^(BOOL allowed) {
                    if (allowed && self.isRunning) {
                        [self scheduleNextTaskCycleWithReason:nil immediate:YES];
                    }
                }];
            } else {
                [self stopRunningWithReason:nil];
            }
        }];
    } else {
        [self.pollTimer invalidate];
        self.pollTimer = nil;
        self.nextFireDate = nil;
        self.isResting = NO;
        [self stopCountdownTimer];
        [self stopHeartbeat];
        [self appendLog:@"已停止"];
    }
}

- (void)loginButtonTapped {
    [self saveCredentials];
    [self loginWithCompletion:^(BOOL success) {
        if (success && self.isRunning) {
            [self startHeartbeatWithCompletion:^(BOOL allowed) {
                if (allowed && self.isRunning) {
                    [self scheduleNextTaskCycleWithReason:nil immediate:YES];
                }
            }];
        }
    }];
}

- (void)runButtonTapped {
    self.isRunning = !self.isRunning;
    [self persistDefaults];
    [self refreshUI];

    if (self.isRunning) {
        [self appendLog:@"已启动"];
        [self refreshPollingState];
        [self startHeartbeatWithCompletion:^(BOOL allowed) {
            if (allowed && self.isRunning) {
                [self scheduleFetchSoon];
            }
        }];
    } else {
        [self appendLog:@"已停止"];
        [self stopHeartbeat];
        [self refreshPollingState];
    }
}

- (void)fetchTaskButtonTapped {
    [self fetchTaskIfPossibleForce:YES];
}

- (void)openTaskButtonTapped {
    if (!self.currentTask) {
        [self appendLog:@"无任务"];
        return;
    }
    [self openCurrentTask];
}

- (void)resetCountButtonTapped {
    self.successCount = 0;
    self.lastRestSuccessCount = 0;
    [self persistDefaults];
    [self refreshUI];
    [self appendLog:@"计数已重置"];
}

- (void)refreshPollingState {
    [self.pollTimer invalidate];
    self.pollTimer = nil;
}

- (void)pollTimerFired {
    [self.pollTimer invalidate];
    self.pollTimer = nil;
    self.nextFireDate = nil;
    [self stopCountdownTimer];
    if (!self.isRunning) {
        return;
    }
    if (self.isResting) {
        self.isResting = NO;
        [self appendLog:@"休息结束，继续任务"];
        [self persistDefaults];
        [self refreshUI];
    }
    if (self.currentTask) {
        [self openCurrentTask];
        return;
    }
    [self fetchTaskIfPossibleForce:NO];
}

- (void)scheduleFetchSoon {
    [self scheduleNextTaskCycleWithReason:nil immediate:YES];
}

- (void)toggleMiniMode {
    self.isMiniMode = !self.isMiniMode;
    [self persistDefaults];
    [self refreshUI];
}

- (void)toggleRestMode {
    self.isRestModeEnabled = !self.isRestModeEnabled;
    if (self.isRestModeEnabled) {
        self.lastRestSuccessCount = self.successCount;
    } else if (self.isResting) {
        self.isResting = NO;
        [self.pollTimer invalidate];
        self.pollTimer = nil;
        self.nextFireDate = nil;
        [self stopCountdownTimer];
        if (self.isRunning) {
            [self scheduleNextTaskCycleWithReason:@"已关闭休息" immediate:YES];
        }
    }
    [self persistDefaults];
    [self refreshUI];
}

- (void)miniViewTapped {
    self.isCollapsed = NO;
    [self persistDefaults];
    [self refreshUI];
}

- (void)handleMiniPan:(UIPanGestureRecognizer *)gesture {
    CGPoint translation = [gesture translationInView:self.overlayWindow.rootViewController.view];
    if (gesture.state == UIGestureRecognizerStateChanged || gesture.state == UIGestureRecognizerStateEnded) {
        CGPoint origin = self.miniOrigin;
        origin.x += translation.x;
        origin.y += translation.y;
        self.miniOrigin = origin;
        [gesture setTranslation:CGPointZero inView:self.overlayWindow.rootViewController.view];
        [self layoutInterface];
    }
}

- (void)updateMiniViewContent {
    NSString *status = self.isRunning ? @"运行中" : @"已暂停";
    NSString *count = [NSString stringWithFormat:@"成功:%ld", (long)self.successCount];
    NSString *countdown = @"";
    if (self.nextFireDate && self.isRunning) {
        NSTimeInterval remaining = [self.nextFireDate timeIntervalSinceNow];
        if (remaining > 0.0) {
            countdown = [NSString stringWithFormat:@" | %.0fs", remaining];
        }
    }
    self.miniInfoLabel.text = [NSString stringWithFormat:@"%@ | %@%@", status, count, countdown];
}

- (void)startCountdownTimer {
    [self stopCountdownTimer];
    if (!self.isMiniMode && !self.isResting) {
        return;
    }
    self.countdownTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(countdownTick) userInfo:nil repeats:YES];
}

- (void)stopCountdownTimer {
    [self.countdownTimer invalidate];
    self.countdownTimer = nil;
}

- (void)countdownTick {
    if (self.isResting) {
        [self refreshUI];
    }
    [self updateMiniViewContent];
    if (!self.nextFireDate || [self.nextFireDate timeIntervalSinceNow] <= 0.0) {
        [self stopCountdownTimer];
    }
}

- (void)installCaptureHooksIfNeeded {
    if (SHPGenericHooksInstalled) {
        return;
    }

    SHPGenericHooksInstalled = YES;

    @try {
        Class sessionClass = objc_getClass("NSURLSession");
        if (sessionClass) {
            MSHookMessageEx(sessionClass, @selector(dataTaskWithRequest:completionHandler:), (IMP)&SHPNSURLSessionDataTaskWithRequestHook, &SHPOriginalNSURLSessionDataTaskWithRequestIMP);
            MSHookMessageEx(sessionClass, @selector(dataTaskWithURL:completionHandler:), (IMP)&SHPNSURLSessionDataTaskWithURLHook, &SHPOriginalNSURLSessionDataTaskWithURLIMP);
        }

        Class jsonClass = objc_getClass("NSJSONSerialization");
        if (jsonClass) {
            MSHookMessageEx(object_getClass(jsonClass), @selector(JSONObjectWithData:options:error:), (IMP)&SHPNSJSONSerializationJSONObjectWithDataHook, &SHPOriginalNSJSONSerializationJSONObjectWithDataIMP);
        }

        [self appendLog:@"Hook 已安装"];
    } @catch (NSException *exception) {
        SHPGenericHooksInstalled = NO;
        [self appendLog:[NSString stringWithFormat:@"Hook异常:%@", exception.reason ?: exception.description]];
    }
}

- (void)installShopeeSpecificHooksIfNeeded {
    if (!kSHPEnableShopeeSpecificHooks || SHPShopeeSpecificHooksInstalled) {
        return;
    }

    @try {
        SHPInstallShopeeSpecificHooks();
        SHPShopeeSpecificHooksInstalled = YES;
        [self appendLog:@"Shopee Hook 已安装"];
    } @catch (NSException *exception) {
        [self appendLog:[NSString stringWithFormat:@"Shopee Hook异常:%@", exception.reason ?: exception.description]];
    }
}

- (void)scheduleNextTaskCycleWithReason:(NSString *)reason immediate:(BOOL)immediate {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self scheduleNextTaskCycleWithReason:reason immediate:immediate];
        });
        return;
    }

    [self.pollTimer invalidate];
    self.pollTimer = nil;

    if (!self.isRunning) {
        return;
    }

    NSTimeInterval delay = immediate ? 0.2 : [self randomTaskDelay];
    if (!immediate) {
        [self appendLog:[NSString stringWithFormat:@"%.0fs后继续", delay]];
    }

    self.nextFireDate = [NSDate dateWithTimeIntervalSinceNow:delay];
    [self startCountdownTimer];

    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:delay target:self selector:@selector(pollTimerFired) userInfo:nil repeats:NO];
}

- (BOOL)scheduleRestIfNeededAfterSuccess {
    if (!self.isRunning || !self.isRestModeEnabled || self.isResting) {
        return NO;
    }

    NSInteger threshold = [self currentRestCountThreshold];
    NSInteger completedSinceRest = self.successCount - self.lastRestSuccessCount;
    if (completedSinceRest < threshold) {
        return NO;
    }

    NSTimeInterval delay = [self currentRestDuration];
    self.isResting = YES;
    self.lastRestSuccessCount = self.successCount;
    [self.pollTimer invalidate];
    self.pollTimer = nil;
    self.nextFireDate = [NSDate dateWithTimeIntervalSinceNow:delay];
    [self startCountdownTimer];
    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:delay target:self selector:@selector(pollTimerFired) userInfo:nil repeats:NO];
    [self persistDefaults];
    [self refreshUI];
    [self appendLog:[NSString stringWithFormat:@"每%ld个成功后休息%.0f分钟", (long)threshold, delay / 60.0]];
    return YES;
}

- (void)sendJSONRequestToURL:(NSString *)urlString
                      method:(NSString *)method
                        body:(NSDictionary *)body
                  authorized:(BOOL)authorized
                  completion:(void (^)(NSInteger statusCode, id jsonObject, NSData *data, NSError *error))completion {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) {
        if (completion) {
            completion(0, nil, nil, [NSError errorWithDomain:@"SHPPlugin" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"非法 URL"}]);
        }
        return;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = method ?: @"GET";
    if (body || [[request.HTTPMethod uppercaseString] isEqualToString:@"POST"]) {
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    }
    if ([urlString isEqualToString:kSHPTakeTaskURL]) {
        [request setValue:@"application/json, text/plain, */*" forHTTPHeaderField:@"Accept"];
    } else {
        [request setValue:@"*/*" forHTTPHeaderField:@"Accept"];
    }
    if ([urlString isEqualToString:kSHPLoginURL]) {
        [request setValue:@"keep-alive" forHTTPHeaderField:@"Connection"];
    }
    if (authorized && self.token.length) {
        [request setValue:[NSString stringWithFormat:@"Bearer %@", self.token] forHTTPHeaderField:@"Authorization"];
    }

    if (body) {
        NSError *jsonError = nil;
        NSData *bodyData = [NSJSONSerialization dataWithJSONObject:body options:0 error:&jsonError];
        if (!jsonError && bodyData.length) {
            request.HTTPBody = bodyData;
        }
    }

    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSInteger statusCode = 0;
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            statusCode = ((NSHTTPURLResponse *)response).statusCode;
        }

        id jsonObject = nil;
        if (data.length) {
            jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        }

        if (completion) {
            SHPDispatchOnMainThread(^{
                completion(statusCode, jsonObject, data, error);
            });
        }
    }];
    [task resume];
}

- (void)sendGzippedJSONRequestToURL:(NSString *)urlString
                               body:(NSDictionary *)body
                         completion:(void (^)(NSInteger statusCode, id jsonObject, NSData *data, NSError *error))completion {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) {
        if (completion) {
            completion(0, nil, nil, [NSError errorWithDomain:@"SHPPlugin" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"invalid URL"}]);
        }
        return;
    }

    NSError *jsonError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:(body ?: @{}) options:0 error:&jsonError];
    NSData *gzippedData = jsonError ? nil : SHPGzipData(jsonData);
    if (!gzippedData.length) {
        if (completion) {
            completion(0, nil, nil, jsonError ?: [NSError errorWithDomain:@"SHPPlugin" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"gzip failed"}]);
        }
        return;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.HTTPBody = gzippedData;
    [request setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"gzip" forHTTPHeaderField:@"Content-Encoding"];
    [request setValue:@"*/*" forHTTPHeaderField:@"Accept"];

    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSInteger statusCode = 0;
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            statusCode = ((NSHTTPURLResponse *)response).statusCode;
        }

        id jsonObject = nil;
        if (data.length) {
            jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        }

        if (completion) {
            SHPDispatchOnMainThread(^{
                completion(statusCode, jsonObject, data, error);
            });
        }
    }];
    [task resume];
}

- (NSString *)extractTokenFromObject:(id)object {
    NSDictionary *root = SHPDictionaryValue(object);
    NSDictionary *data = SHPDictionaryValue(root[@"data"]);
    NSString *exactToken = SHPStringValue(data[@"token"]);
    if (exactToken.length) {
        return exactToken;
    }

    NSArray<NSString *> *candidates = @[@"access_token", @"token", @"jwt", @"accessToken"];
    NSString *direct = SHPFindStringForKeys(object, candidates);
    if (direct.length) {
        return direct;
    }

    NSString *raw = SHPJSONStringFromObject(object);
    if (!raw.length) {
        return nil;
    }

    NSString *regexToken = SHPRegexFirstMatch(raw, @"\"(?:access_token|accessToken|token|jwt)\"\\s*:\\s*\"([^\"]+)\"", 1);
    return regexToken;
}

- (void)clearPendingSubmissionState {
    self.pendingSubmitJSONString = nil;
    self.pendingSubmitSourceURL = nil;
    self.waitingForPDP = NO;
}

- (NSString *)api2Number {
    return SHPStringValue(self.passwordField.text) ?: [self savedPassword] ?: @"";
}

- (NSDictionary *)controlPayloadWithAction:(NSString *)action username:(NSString *)username extra:(NSDictionary *)extra {
    NSMutableDictionary *payload = [NSMutableDictionary dictionary];
    if (action.length) {
        payload[@"act"] = action;
    }
    NSString *resolvedUsername = SHPStringValue(username) ?: SHPStringValue(self.usernameField.text) ?: [self savedUsername];
    if (self.apiType == 2 && [action isEqualToString:@"heartbeat"]) {
        NSString *api2Number = [self api2Number];
        if (api2Number.length) {
            resolvedUsername = api2Number;
        }
    }
    if (resolvedUsername.length) {
        payload[@"username"] = resolvedUsername;
    }
    if (self.deviceID.length) {
        payload[@"device_id"] = self.deviceID;
        payload[@"fingerprint_key"] = self.deviceID;
    }
    if (self.groupID.length) {
        payload[@"group_id"] = self.groupID;
    }
    NSInteger payloadApiType = [action isEqualToString:@"api1_login"] ? 1 : (self.apiType == 2 ? 2 : 1);
    payload[@"api_type"] = @(payloadApiType);
    payload[@"client"] = @"ShopeeTaskHook";
    payload[@"platform"] = @"ios";
    payload[@"device_type"] = @"ios";
    payload[@"bundle_id"] = kSHPBundleID;
    payload[@"appVersion"] = kSHPSubmitAppVersion;
    if (extra.count) {
        [payload addEntriesFromDictionary:extra];
    }
    return payload.copy;
}

- (BOOL)responseObjectAllowsAccess:(id)object {
    NSDictionary *dict = SHPDictionaryValue(object);
    if (!dict.count) {
        return YES;
    }

    id allowedValue = dict[@"allowed"];
    if ([allowedValue respondsToSelector:@selector(boolValue)] && ![allowedValue boolValue]) {
        return NO;
    }

    NSString *code = SHPStringValue(dict[@"code"]);
    if ([code isEqualToString:@"403"]) {
        return NO;
    }

    id okValue = dict[@"ok"];
    if ([okValue respondsToSelector:@selector(boolValue)] && ![okValue boolValue]) {
        return NO;
    }

    return YES;
}

- (NSString *)messageFromResponseObject:(id)object fallback:(NSString *)fallback {
    NSDictionary *dict = SHPDictionaryValue(object);
    NSString *message = SHPStringValue(dict[@"msg"]) ?: SHPStringValue(dict[@"message"]) ?: SHPFindStringForKeys(object, @[@"msg", @"message", @"error"]);
    return message.length ? message : fallback;
}

- (void)stopRunningWithReason:(NSString *)reason {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self stopRunningWithReason:reason];
        });
        return;
    }

    self.isRunning = NO;
    self.isResting = NO;
    [self.pollTimer invalidate];
    self.pollTimer = nil;
    self.nextFireDate = nil;
    [self stopCountdownTimer];
    [self stopHeartbeat];
    [self persistDefaults];
    [self refreshUI];
    if (reason.length) {
        [self appendLog:reason];
    }
}

- (void)sendHeartbeatWithCompletion:(void (^)(BOOL allowed))completion {
    NSString *username = SHPStringValue(self.usernameField.text) ?: [self savedUsername];
    NSDictionary *payload = [self controlPayloadWithAction:@"heartbeat" username:username extra:nil];
    [self sendJSONRequestToURL:kSHPControlURL method:@"POST" body:payload authorized:NO completion:^(NSInteger statusCode, id jsonObject, NSData *data, NSError *error) {
        (void)data;
        if (error) {
            [self appendLog:[NSString stringWithFormat:@"心跳失败:%@", error.localizedDescription ?: @"err"]];
            if (completion) {
                completion(YES);
            }
            return;
        }

        if (![self responseObjectAllowsAccess:jsonObject]) {
            NSString *message = [self messageFromResponseObject:jsonObject fallback:[NSString stringWithFormat:@"心跳拒绝 HTTP=%ld", (long)statusCode]];
            [self stopRunningWithReason:[NSString stringWithFormat:@"账号/设备未授权:%@", message]];
            if (completion) {
                completion(NO);
            }
            return;
        }

        if (completion) {
            completion(YES);
        }
    }];
}

- (void)heartbeatTimerFired {
    if (!self.isRunning) {
        [self stopHeartbeat];
        return;
    }
    [self sendHeartbeatWithCompletion:nil];
}

- (void)startHeartbeatWithCompletion:(void (^)(BOOL allowed))completion {
    [self stopHeartbeat];
    if (!self.isRunning) {
        if (completion) {
            completion(NO);
        }
        return;
    }
    [self sendHeartbeatWithCompletion:^(BOOL allowed) {
        if (allowed && self.isRunning) {
            self.heartbeatTimer = [NSTimer scheduledTimerWithTimeInterval:kSHPHeartbeatInterval target:self selector:@selector(heartbeatTimerFired) userInfo:nil repeats:YES];
        }
        if (completion) {
            completion(allowed);
        }
    }];
}

- (void)startHeartbeat {
    [self startHeartbeatWithCompletion:nil];
}

- (void)stopHeartbeat {
    [self.heartbeatTimer invalidate];
    self.heartbeatTimer = nil;
}

- (void)finishCurrentTaskAndContinueWithSuccess:(BOOL)success reason:(NSString *)reason {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self finishCurrentTaskAndContinueWithSuccess:success reason:reason];
        });
        return;
    }

    self.submittingCurrentTask = NO;
    if (success) {
        self.successCount += 1;
    }

    self.currentTask = nil;
    [self clearPendingSubmissionState];
    [self persistDefaults];
    [self refreshUI];

    if (success) {
        [self appendLog:[NSString stringWithFormat:@"成功#%ld", (long)self.successCount]];
    } else if (reason.length) {
        [self appendLog:reason];
    }

    if (success && [self scheduleRestIfNeededAfterSuccess]) {
        return;
    }

    if (self.isRunning) {
        [self scheduleNextTaskCycleWithReason:(success ? @"任务完成" : @"任务失败，继续下一条") immediate:NO];
    }
}

- (void)loginApi1WithUsername:(NSString *)username password:(NSString *)password completion:(void (^)(BOOL success))completion {
    [self appendLog:@"接口1登录中..."];
    NSDictionary *loginBody = [self controlPayloadWithAction:@"api1_login" username:username extra:@{@"password": password}];
    [self sendJSONRequestToURL:kSHPLoginURL method:@"POST" body:loginBody authorized:NO completion:^(NSInteger statusCode, id jsonObject, NSData *data, NSError *error) {
        if (error) {
            [self appendLog:[NSString stringWithFormat:@"登录失败:%@", error.localizedDescription ?: @"err"]];
            if (completion) {
                completion(NO);
            }
            return;
        }

        if (![self responseObjectAllowsAccess:jsonObject]) {
            NSString *message = [self messageFromResponseObject:jsonObject fallback:[NSString stringWithFormat:@"HTTP=%ld", (long)statusCode]];
            [self appendLog:[NSString stringWithFormat:@"登录拒绝:%@", message]];
            if (completion) {
                completion(NO);
            }
            return;
        }

        NSString *token = [self extractTokenFromObject:jsonObject];
        if (!token.length && data.length) {
            NSString *rawString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            token = SHPRegexFirstMatch(rawString, @"\"(?:access_token|accessToken|token|jwt)\"\\s*:\\s*\"([^\"]+)\"", 1);
        }

        if (!token.length) {
            [self appendLog:[NSString stringWithFormat:@"登录无token HTTP=%ld", (long)statusCode]];
            if (completion) {
                completion(NO);
            }
            return;
        }

        self.token = token;
        self.groupID = nil;
        self.apiType = 1;
        [self persistDefaults];
        [self appendLog:@"接口1登录成功"];
        [self refreshUI];
        if (completion) {
            completion(YES);
        }
    }];
}

- (void)loginWithCompletion:(void (^)(BOOL success))completion {
    NSString *username = SHPStringValue(self.usernameField.text) ?: [self savedUsername];
    NSString *password = SHPStringValue(self.passwordField.text) ?: [self savedPassword];

    if (username.length && password.length) {
        [self appendLog:@"接口2登录中..."];
        NSDictionary *api2Body = [self controlPayloadWithAction:@"api2_login" username:kSHPApi2FixedUsername extra:@{@"password": password}];
        [self sendJSONRequestToURL:kSHPLoginURL method:@"POST" body:api2Body authorized:NO completion:^(NSInteger api2StatusCode, id api2JsonObject, NSData *api2Data, NSError *api2Error) {
            (void)api2Data;
            if (!api2Error && [self responseObjectAllowsAccess:api2JsonObject]) {
                NSString *api2Token = [self extractTokenFromObject:api2JsonObject];
                NSDictionary *root = SHPDictionaryValue(api2JsonObject);
                NSDictionary *data = SHPDictionaryValue(root[@"data"]);
                NSString *groupID = SHPStringValue(data[@"groupId"]) ?: SHPStringValue(data[@"group_id"]) ?: kSHPApi2FixedUsername;
                if (api2Token.length) {
                    self.token = api2Token;
                    self.groupID = groupID;
                    self.apiType = 2;
                    [self persistDefaults];
                    [self appendLog:@"接口2登录成功"];
                    [self refreshUI];
                    if (completion) {
                        completion(YES);
                    }
                    return;
                }
            } else {
                NSString *message = [self messageFromResponseObject:api2JsonObject fallback:(api2Error.localizedDescription ?: [NSString stringWithFormat:@"HTTP=%ld", (long)api2StatusCode])];
                [self appendLog:[NSString stringWithFormat:@"接口2登录失败:%@", message ?: @"-"]];
            }

            [self loginApi1WithUsername:username password:password completion:completion];
        }];
        return;
    }

    if (!username.length || !password.length) {
        [self appendLog:@"请填写账号密码"];
        [self refreshUI];
        if (completion) {
            completion(NO);
        }
        return;
    }

        [self appendLog:@"登录中..."];
    NSDictionary *loginBody = [self controlPayloadWithAction:@"api1_login" username:username extra:@{@"password": password}];
    [self sendJSONRequestToURL:kSHPLoginURL method:@"POST" body:loginBody authorized:NO completion:^(NSInteger statusCode, id jsonObject, NSData *data, NSError *error) {
        if (error) {
        [self appendLog:[NSString stringWithFormat:@"登录失败:%@", error.localizedDescription ?: @"err"]];
            if (completion) {
                completion(NO);
            }
            return;
        }

        if (![self responseObjectAllowsAccess:jsonObject]) {
            NSString *message = [self messageFromResponseObject:jsonObject fallback:[NSString stringWithFormat:@"HTTP=%ld", (long)statusCode]];
            [self appendLog:[NSString stringWithFormat:@"登录拒绝:%@", message]];
            if (completion) {
                completion(NO);
            }
            return;
        }

        NSString *token = [self extractTokenFromObject:jsonObject];
        if (!token.length && data.length) {
            NSString *rawString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            token = SHPRegexFirstMatch(rawString, @"\"(?:access_token|accessToken|token|jwt)\"\\s*:\\s*\"([^\"]+)\"", 1);
        }

        if (!token.length) {
            [self appendLog:[NSString stringWithFormat:@"登录无token HTTP=%ld", (long)statusCode]];
            if (completion) {
                completion(NO);
            }
            return;
        }

        self.token = token;
        [self persistDefaults];
        [self appendLog:@"登录成功"];
        [self refreshUI];
        if (completion) {
            completion(YES);
        }
    }];
}

- (SHPTask *)buildTaskFromResponseObject:(id)object {
    if (!object || object == [NSNull null]) {
        return nil;
    }

    NSDictionary *root = SHPDictionaryValue(object);
    NSDictionary *payload = root;
    if (root.count) {
        NSString *code = SHPStringValue(root[@"code"]);
        NSDictionary *data = SHPDictionaryValue(root[@"data"]);
        if (data) {
            if (code.length && ![code isEqualToString:@"200"]) {
                return nil;
            }
            payload = data;
        }
    }

    SHPTask *task = [SHPTask new];
    task.rawPayload = payload ?: object;

    task.traceID = SHPStringValue(payload[@"taskId"]) ?: SHPFindStringForKeys(payload, @[@"trace_id", @"traceId", @"request_id", @"requestId", @"task_id", @"taskId", @"id"]);
    task.itemID = SHPStringValue(payload[@"itemId"]) ?: SHPStringValue(payload[@"item_id"]) ?: SHPFindStringForKeys(payload, @[@"item_id", @"itemid", @"itemId"]);
    task.shopID = SHPStringValue(payload[@"shopId"]) ?: SHPStringValue(payload[@"shop_id"]) ?: SHPFindStringForKeys(payload, @[@"shop_id", @"shopid", @"shopId"]);
    task.productURL = SHPStringValue(payload[@"taskUrl"]) ?: SHPStringValue(payload[@"task_url"]) ?: SHPFindStringForKeys(payload, @[@"url", @"link", @"product_url", @"target_url", @"jump_url", @"task_url", @"taskUrl"]);
    task.pdpURL = SHPStringValue(payload[@"pdpUrl"]) ?: SHPStringValue(payload[@"pdp_url"]) ?: SHPFindStringForKeys(payload, @[@"pdp_url", @"pdpUrl", @"detail_url", @"detailUrl", @"api_url", @"apiUrl"]);

    if (task.productURL.length) {
        NSDictionary *ids = SHPExtractIDsFromString(task.productURL);
        if (!task.itemID.length) {
            task.itemID = ids[@"item_id"];
        }
        if (!task.shopID.length) {
            task.shopID = ids[@"shop_id"];
        }
        if (!task.pdpURL.length && [task.productURL containsString:@"/api/v4/pdp/get"]) {
            task.pdpURL = task.productURL;
        }
    }

    if (task.pdpURL.length) {
        NSDictionary *ids = SHPExtractIDsFromString(task.pdpURL);
        if (!task.itemID.length) {
            task.itemID = ids[@"item_id"];
        }
        if (!task.shopID.length) {
            task.shopID = ids[@"shop_id"];
        }
    }

    if (task.shopID.length && task.itemID.length) {
        task.productURL = SHPBuildProductURL(task.shopID, task.itemID);
    } else if (!task.productURL.length) {
        task.productURL = SHPBuildProductURL(task.shopID, task.itemID);
    }

    if (!task.pdpURL.length) {
        task.pdpURL = SHPBuildPDPURL(task.shopID, task.itemID);
    }

    if (!task.traceID.length) {
        task.traceID = NSUUID.UUID.UUIDString;
    }

    if (!task.itemID.length || !task.shopID.length) {
        return nil;
    }
    return task;
}

- (SHPTask *)buildApi2TaskFromResponseObject:(id)object {
    NSDictionary *root = SHPDictionaryValue(object);
    if (!root.count) {
        return nil;
    }
    id okValue = root[@"ok"];
    if ([okValue respondsToSelector:@selector(boolValue)] && ![okValue boolValue]) {
        return nil;
    }

    NSDictionary *taskData = SHPDictionaryValue(root[@"TaskData"]);
    if (!taskData.count) {
        return nil;
    }

    SHPTask *task = [SHPTask new];
    task.rawPayload = taskData;
    task.productURL = SHPStringValue(taskData[@"Url"]) ?: SHPFindStringForKeys(taskData, @[@"url", @"Url"]);
    NSDictionary *taskInfo = SHPDictionaryValue(taskData[@"Task"]);
    task.traceID = SHPStringValue(taskInfo[@"ID"]) ?: SHPStringValue(taskInfo[@"id"]) ?: NSUUID.UUID.UUIDString;

    if (task.productURL.length) {
        NSDictionary *ids = SHPExtractIDsFromString(task.productURL);
        if (!ids.count) {
            ids = SHPExtractTrailingPathIDs(task.productURL);
        }
        task.shopID = ids[@"shop_id"];
        task.itemID = ids[@"item_id"];
    }
    if (task.shopID.length && task.itemID.length) {
        task.productURL = SHPBuildProductURL(task.shopID, task.itemID);
    } else if (!task.productURL.length) {
        task.productURL = SHPBuildProductURL(task.shopID, task.itemID);
    }
    task.pdpURL = SHPBuildPDPURL(task.shopID, task.itemID);
    if (!task.itemID.length || !task.shopID.length) {
        return nil;
    }
    return task;
}

- (void)fetchTaskIfPossibleForce:(BOOL)force {
    if (self.requestInFlight || self.submittingCurrentTask) {
        return;
    }

    if (self.currentTask) {
        if (force) {
            [self appendLog:@"已有任务"];
        }
        return;
    }

    if (!self.token.length) {
        [self appendLog:@"自动登录"];
        [self loginWithCompletion:^(BOOL success) {
            if (success) {
                [self fetchTaskIfPossibleForce:force];
            } else if (self.isRunning) {
                [self scheduleNextTaskCycleWithReason:@"登录失败" immediate:NO];
            }
        }];
        return;
    }

    self.requestInFlight = YES;
    if (self.apiType == 2) {
        NSString *api2Group = self.groupID.length ? self.groupID : kSHPApi2FixedUsername;
        NSString *api2Number = [self api2Number];
        NSString *api2Use = [NSString stringWithFormat:@"%@_%@", api2Group, (api2Number.length ? api2Number : kSHPApi2FixedUsername)];
        [self appendLog:@"接口2取任务..."];
        [self sendGzippedJSONRequestToURL:kSHPApi2TakeTaskURL body:@{@"info": @"\u53f0\u6e7e", @"use": api2Use} completion:^(NSInteger statusCode, id jsonObject, NSData *data, NSError *error) {
            self.requestInFlight = NO;
            if (error) {
                [self appendLog:[NSString stringWithFormat:@"接口2取任务失败:%@", error.localizedDescription ?: @"err"]];
                if (self.isRunning) {
                    [self scheduleNextTaskCycleWithReason:@"接口2取任务失败" immediate:NO];
                }
                return;
            }

            SHPTask *task = [self buildApi2TaskFromResponseObject:jsonObject];
            if (!task) {
                NSString *message = [self messageFromResponseObject:jsonObject fallback:[NSString stringWithFormat:@"HTTP=%ld", (long)statusCode]];
                if (!jsonObject && data.length) {
                    message = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: message;
                } else if (jsonObject) {
                    NSString *rawJSON = SHPJSONStringFromObject(jsonObject);
                    if (rawJSON.length) {
                        message = [message stringByAppendingFormat:@" %@", rawJSON];
                    }
                }
                [self appendLog:[NSString stringWithFormat:@"接口2暂无任务:%@", message ?: @"-"]];
                if (self.isRunning) {
                    [self scheduleNextTaskCycleWithReason:@"接口2暂无任务" immediate:NO];
                }
                return;
            }

            self.currentTask = task;
            [self persistDefaults];
            [self refreshUI];
            [self appendLog:[NSString stringWithFormat:@"接口2任务 %@/%@", task.shopID, task.itemID]];
            [self openCurrentTask];
        }];
        return;
    }
        [self appendLog:@"取任务..."];
    [self sendJSONRequestToURL:kSHPTakeTaskURL method:@"GET" body:nil authorized:YES completion:^(NSInteger statusCode, id jsonObject, NSData *data, NSError *error) {
        self.requestInFlight = NO;

        if (statusCode == 401) {
            self.token = nil;
            [self persistDefaults];
            [self appendLog:@"401,重新登录"];
            [self loginWithCompletion:^(BOOL success) {
                if (success) {
                    [self fetchTaskIfPossibleForce:force];
                } else if (self.isRunning) {
                    [self scheduleNextTaskCycleWithReason:@"重新登录失败" immediate:NO];
                }
            }];
            return;
        }

        if (error) {
            [self appendLog:[NSString stringWithFormat:@"取任务失败:%@", error.localizedDescription ?: @"err"]];
            if (self.isRunning) {
                [self scheduleNextTaskCycleWithReason:@"取任务失败" immediate:NO];
            }
            return;
        }

        if (!jsonObject && data.length) {
            NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            [self appendLog:[NSString stringWithFormat:@"返回数据异常:%@", raw ?: @""]];
            if (self.isRunning) {
                [self scheduleNextTaskCycleWithReason:@"返回数据异常" immediate:NO];
            }
            return;
        }

        NSString *bizCode = SHPStringValue([SHPDictionaryValue(jsonObject) objectForKey:@"code"]);
        NSString *bizMsg = SHPStringValue([SHPDictionaryValue(jsonObject) objectForKey:@"msg"]);
        SHPTask *task = [self buildTaskFromResponseObject:jsonObject];
        if (!task) {
            if (bizCode.length || bizMsg.length) {
                [self appendLog:[NSString stringWithFormat:@"无任务 code=%@ msg=%@", bizCode ?: @"-", bizMsg ?: @"-"]];
            } else {
                [self appendLog:[NSString stringWithFormat:@"无任务 HTTP=%ld", (long)statusCode]];
            }
            if (self.isRunning) {
                [self scheduleNextTaskCycleWithReason:@"暂未取到任务" immediate:NO];
            }
            return;
        }

        self.currentTask = task;
        [self persistDefaults];
        [self refreshUI];
        [self appendLog:[NSString stringWithFormat:@"任务 %@/%@", task.shopID, task.itemID]];
        [self openCurrentTask];
    }];
}

- (BOOL)handleNoDataCaptureWithMessage:(NSString *)message currentItemID:(NSString *)currentItemID {
    (void)currentItemID;
    self.consecutivePDPFailures += 1;
    [self appendLog:[NSString stringWithFormat:@"%@（连续%ld次）", message, (long)self.consecutivePDPFailures]];
    if (self.consecutivePDPFailures >= 2) {
        [self handleRiskControlDetectedWithMessage:@"连续两次未获取到数据，疑似触发风控或验证码，请手动查看，已自动暂停"];
        return YES;
    }
    if (self.isRunning) {
        [self finishCurrentTaskAndContinueWithSuccess:NO reason:[NSString stringWithFormat:@"%@，已跳过", message]];
    }
    return NO;
}

- (BOOL)isUsableMainWindow:(UIWindow *)window {
    if (!window || window == self.overlayWindow) {
        return NO;
    }

    if ([window isKindOfClass:[SHPPassthroughWindow class]]) {
        return NO;
    }

    if (window.hidden || window.alpha < 0.01 || !window.rootViewController) {
        return NO;
    }

    if (window.windowLevel > UIWindowLevelNormal + 1.0) {
        return NO;
    }

    return YES;
}

- (NSArray<UIWindow *> *)candidateWindows {
    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];

    if (@available(iOS 13.0, *)) {
        UIWindowScene *scene = [self activeWindowScene];
        if (scene.windows.count) {
            [windows addObjectsFromArray:scene.windows];
        }
    }

    NSArray<UIWindow *> *legacyWindows = [[UIApplication sharedApplication] valueForKey:@"windows"];
    for (UIWindow *window in legacyWindows) {
        if (![windows containsObject:window]) {
            [windows addObject:window];
        }
    }

    return windows.copy;
}

- (UIWindow *)mainApplicationWindow {
    NSArray<UIWindow *> *windows = [self candidateWindows];

    for (UIWindow *window in windows) {
        if ([self isUsableMainWindow:window] && window.isKeyWindow) {
            return window;
        }
    }

    for (UIWindow *window in windows) {
        if ([self isUsableMainWindow:window] && window.windowLevel <= UIWindowLevelNormal + 0.1) {
            return window;
        }
    }

    for (UIWindow *window in windows) {
        if ([self isUsableMainWindow:window]) {
            return window;
        }
    }

    return nil;
}

- (UIViewController *)resolvedTopViewControllerFromController:(UIViewController *)controller {
    UIViewController *current = controller;
    BOOL advanced = YES;

    while (current && advanced) {
        advanced = NO;

        UIViewController *presented = current.presentedViewController;
        if (presented && ![presented isKindOfClass:[UIAlertController class]]) {
            current = presented;
            advanced = YES;
            continue;
        }

        if ([current isKindOfClass:[UITabBarController class]]) {
            UIViewController *selected = ((UITabBarController *)current).selectedViewController;
            if (selected && selected != current) {
                current = selected;
                advanced = YES;
                continue;
            }
        }

        if ([current isKindOfClass:[UINavigationController class]]) {
            UINavigationController *navigationController = (UINavigationController *)current;
            UIViewController *visible = navigationController.visibleViewController ?: navigationController.topViewController;
            if (visible && visible != current) {
                current = visible;
                advanced = YES;
            }
        }
    }

    if ([current isKindOfClass:[UIAlertController class]] && current.presentingViewController) {
        current = current.presentingViewController;
    }

    return current;
}

- (void)popToRootViewControllerIfNeeded {
    UIWindow *window = [self mainApplicationWindow];
    UIViewController *rootController = window.rootViewController;
    UIViewController *topController = [self resolvedTopViewControllerFromController:rootController];
    UINavigationController *navigationController = nil;

    if ([topController isKindOfClass:[UINavigationController class]]) {
        navigationController = (UINavigationController *)topController;
    } else {
        navigationController = topController.navigationController;
    }

    if (!navigationController && [rootController isKindOfClass:[UITabBarController class]]) {
        UIViewController *selected = ((UITabBarController *)rootController).selectedViewController;
        if ([selected isKindOfClass:[UINavigationController class]]) {
            navigationController = (UINavigationController *)selected;
        } else {
            navigationController = selected.navigationController;
        }
    }

    if (!navigationController && [rootController isKindOfClass:[UINavigationController class]]) {
        navigationController = (UINavigationController *)rootController;
    }

    if (navigationController.viewControllers.count > 1) {
        [navigationController popToRootViewControllerAnimated:NO];
    }
}

- (UIViewController *)topViewController {
    UIWindow *mainWindow = [self mainApplicationWindow];
    if (!mainWindow.rootViewController) {
        return nil;
    }

    return [self resolvedTopViewControllerFromController:mainWindow.rootViewController];
}

- (id)buildNavigationPathObjectForRoute:(NSString *)route {
    if (!route.length) {
        return nil;
    }

    Class pathClass = SHPResolveRuntimeClass(@[@"SHPNavigatorNavigationPath"]);
    if (pathClass) {
        NSArray<NSString *> *classSelectors = @[
            @"pathWithAppRL:",
            @"navigationPathWithAppRL:",
            @"pathWithString:",
            @"navigationPathWithString:",
            @"pathWithRoute:"
        ];

        for (NSString *selectorName in classSelectors) {
            SEL selector = NSSelectorFromString(selectorName);
            if (![pathClass respondsToSelector:selector]) {
                continue;
            }
            @try {
                id candidate = ((id (*)(id, SEL, id))objc_msgSend)(pathClass, selector, route);
                if (candidate) {
                    return candidate;
                }
            } @catch (__unused NSException *exception) {}
        }

        NSArray<NSString *> *initSelectors = @[
            @"initWithAppRL:",
            @"initWithString:",
            @"initWithRoute:"
        ];

        for (NSString *selectorName in initSelectors) {
            SEL selector = NSSelectorFromString(selectorName);
            id instance = [pathClass alloc];
            if (![instance respondsToSelector:selector]) {
                continue;
            }
            @try {
                id candidate = ((id (*)(id, SEL, id))objc_msgSend)(instance, selector, route);
                if (candidate) {
                    return candidate;
                }
            } @catch (__unused NSException *exception) {}
        }
    }

    return [SHPFallbackNavigationPath pathWithAppRL:route];
}

- (id)resolvedNavigationManager {
    NSArray<NSString *> *managerClassNames = @[@"BTAppManager", @"BTApplicationAddonProvider", @"SHPNavigator"];
    NSArray<NSString *> *sharedSelectors = @[@"sharedInstance", @"sharedManager", @"defaultManager", @"manager", @"shared"];
    NSArray<NSString *> *nestedSelectors = @[@"appManager", @"navigationManager", @"defaultManager", @"manager", @"navigator", @"navigatorManager", @"pageNavigator", @"router"];

    for (NSString *className in managerClassNames) {
        Class candidateClass = SHPResolveRuntimeClass(@[className]);
        if (!candidateClass) {
            continue;
        }

        for (NSString *sharedName in sharedSelectors) {
            SEL sharedSelector = NSSelectorFromString(sharedName);
            if (![candidateClass respondsToSelector:sharedSelector]) {
                continue;
            }

            id candidate = ((id (*)(id, SEL))objc_msgSend)(candidateClass, sharedSelector);
            if (!candidate) {
                continue;
            }

            SEL navigateSelector = NSSelectorFromString(@"navigateFromViewController:destinationPath:navigateOption:completion:");
            SEL pushSelector = NSSelectorFromString(@"pushFromViewController:destinationPath:pushOption:completion:");
            if ([candidate respondsToSelector:navigateSelector] || [candidate respondsToSelector:pushSelector]) {
                return candidate;
            }

            for (NSString *nestedName in nestedSelectors) {
                id nested = SHPCallNoArgObject(candidate, nestedName);
                if (!nested) {
                    continue;
                }
                if ([nested respondsToSelector:navigateSelector] || [nested respondsToSelector:pushSelector]) {
                    return nested;
                }
            }
        }
    }

    return nil;
}

- (BOOL)invokeSelector:(SEL)selector onTarget:(id)target arguments:(NSArray *)arguments {
    if (!target || !selector) {
        return NO;
    }

    NSMethodSignature *signature = [target methodSignatureForSelector:selector];
    if (!signature) {
        return NO;
    }

    NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
    invocation.target = target;
    invocation.selector = selector;

    NSUInteger expected = signature.numberOfArguments > 2 ? signature.numberOfArguments - 2 : 0;
    NSUInteger provided = arguments.count;
    NSUInteger count = MIN(expected, provided);
    for (NSUInteger index = 0; index < count; index++) {
        id value = arguments[index];
        if (value == [NSNull null]) {
            value = nil;
        }
        const char *argType = [signature getArgumentTypeAtIndex:index + 2];
        if (argType && argType[0] == '@') {
            id obj = value;
            [invocation setArgument:&obj atIndex:index + 2];
        } else {
            long long zero = 0;
            [invocation setArgument:&zero atIndex:index + 2];
        }
    }

    for (NSUInteger index = count; index < expected; index++) {
        const char *argType = [signature getArgumentTypeAtIndex:index + 2];
        if (argType && argType[0] == '@') {
            id nilObject = nil;
            [invocation setArgument:&nilObject atIndex:index + 2];
        } else {
            long long zero = 0;
            [invocation setArgument:&zero atIndex:index + 2];
        }
    }

    @try {
        [invocation invoke];
        return YES;
    } @catch (NSException *exception) {
        [self appendLog:[NSString stringWithFormat:@"导航异常:%@", exception.reason ?: exception.description]];
        return NO;
    }
}

- (BOOL)invokeRouteNavigationOnManager:(id)manager topController:(UIViewController *)topController route:(NSString *)route {
    if (!manager || !topController || !route.length) {
        return NO;
    }

    id pathObject = [self buildNavigationPathObjectForRoute:route];
    if (!pathObject) {
        return NO;
    }

    SEL navigateSelector = NSSelectorFromString(@"navigateFromViewController:destinationPath:navigateOption:completion:");
    if ([manager respondsToSelector:navigateSelector]) {
        if ([self invokeSelector:navigateSelector onTarget:manager arguments:@[topController, pathObject, [NSNull null], [NSNull null]]]) {
            [self appendLog:@"跳转成功"];
            return YES;
        }
    }

    SEL pushSelector = NSSelectorFromString(@"pushFromViewController:destinationPath:pushOption:completion:");
    if ([manager respondsToSelector:pushSelector]) {
        if ([self invokeSelector:pushSelector onTarget:manager arguments:@[topController, pathObject, [NSNull null], [NSNull null]]]) {
            [self appendLog:@"跳转成功"];
            return YES;
        }
    }

    SEL directSelector = NSSelectorFromString(@"navigateToProduct:goodID:");
    if ([manager respondsToSelector:directSelector]) {
        if ([self invokeSelector:directSelector onTarget:manager arguments:@[self.currentTask.shopID ?: @"", self.currentTask.itemID ?: @""]]) {
            [self appendLog:@"跳转成功"];
            return YES;
        }
    }

    SEL directSelector2 = NSSelectorFromString(@"openProductPage:goodID:");
    if ([manager respondsToSelector:directSelector2]) {
        if ([self invokeSelector:directSelector2 onTarget:manager arguments:@[self.currentTask.shopID ?: @"", self.currentTask.itemID ?: @""]]) {
            [self appendLog:@"跳转成功"];
            return YES;
        }
    }

    SEL directSelector3 = NSSelectorFromString(@"openProduct:goodID:");
    if ([manager respondsToSelector:directSelector3]) {
        if ([self invokeSelector:directSelector3 onTarget:manager arguments:@[self.currentTask.shopID ?: @"", self.currentTask.itemID ?: @""]]) {
            [self appendLog:@"跳转成功"];
            return YES;
        }
    }

    return NO;
}

- (BOOL)navigateWithBTManagerToRoute:(NSString *)route {
    if (!route.length) {
        [self appendLog:@"跳转失败: route为空"];
        return NO;
    }

    id manager = [self resolvedNavigationManager];
    if (!manager) {
        [self appendLog:@"跳转失败:无导航器"];
        return NO;
    }

    UIViewController *topController = [self topViewController];
    if (!topController) {
        [self appendLog:@"跳转失败:无控制器"];
        return NO;
    }

    NSMutableArray<NSString *> *routes = [NSMutableArray array];
    if (route.length) {
        [routes addObject:route];
    }
    if (self.currentTask.shopID.length && self.currentTask.itemID.length) {
        [routes addObject:[NSString stringWithFormat:@"rn/PRODUCT_PAGE?item_id=%@&shop_id=%@", self.currentTask.itemID, self.currentTask.shopID]];
        [routes addObject:[NSString stringWithFormat:@"rn/PRODUCT_PAGE?good_id=%@&shop_id=%@", self.currentTask.itemID, self.currentTask.shopID]];
        [routes addObject:[NSString stringWithFormat:@"rn/PRODUCT_PAGE?shopid=%@&itemid=%@", self.currentTask.shopID, self.currentTask.itemID]];
        [routes addObject:[NSString stringWithFormat:@"PRODUCT_PAGE?itemid=%@&shopid=%@", self.currentTask.itemID, self.currentTask.shopID]];
    }

    for (NSString *candidateRoute in routes) {
        if ([self invokeRouteNavigationOnManager:manager topController:topController route:candidateRoute]) {
            return YES;
        }
    }

    [self appendLog:@"跳转失败:路由无响应"];
    return NO;
}

- (void)openCurrentTask {
    if (![NSThread isMainThread]) {
        SHPDispatchOnMainThread(^{
            [self openCurrentTask];
        });
        return;
    }

    if (!self.currentTask) {
        [self appendLog:@"没有待打开的任务"];
        return;
    }

    [self installCaptureHooksIfNeeded];
    self.waitingForPDP = YES;

    NSString *route = nil;
    if (self.currentTask.itemID.length && self.currentTask.shopID.length) {
        route = [NSString stringWithFormat:@"rn/PRODUCT_PAGE?itemid=%@&shopid=%@", self.currentTask.itemID, self.currentTask.shopID];
    }

    [self popToRootViewControllerIfNeeded];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if ([self navigateWithBTManagerToRoute:route]) {
            return;
        }

        NSString *fallbackURL = self.currentTask.productURL ?: SHPBuildProductURL(self.currentTask.shopID, self.currentTask.itemID);
        NSURL *url = [NSURL URLWithString:fallbackURL];
        if (url) {
            NSDictionary *universalLinkOnly = @{UIApplicationOpenURLOptionUniversalLinksOnly: @YES};
            [[UIApplication sharedApplication] openURL:url options:universalLinkOnly completionHandler:^(BOOL success) {
                if (success) {
                    [self appendLog:@"Universal Link跳转成功"];
                    return;
                }

                [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
                [self appendLog:@"回退链接跳转"];
            }];
            return;
        }

        [self appendLog:@"跳转失败:无URL"];
    });

    NSString *currentItemID = self.currentTask.itemID;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (!self.waitingForPDP || self.submittingCurrentTask || !self.currentTask) {
            return;
        }
        if (![self.currentTask.itemID isEqualToString:currentItemID]) {
            return;
        }
        if ([self handleNoDataCaptureWithMessage:@"获取数据超时" currentItemID:currentItemID]) {
            return;
        }
    });
}

- (BOOL)currentTaskMatchesJSONObject:(id)object rawData:(NSData *)rawData {
    if (!self.currentTask || self.submittingCurrentTask) {
        return NO;
    }

    NSString *itemID = self.currentTask.itemID;
    NSString *shopID = self.currentTask.shopID;
    if (!itemID.length || !shopID.length) {
        return NO;
    }

    NSString *rawString = nil;
    if (rawData.length) {
        rawString = [[NSString alloc] initWithData:rawData encoding:NSUTF8StringEncoding];
    }

    if (rawString.length && ([rawString containsString:@"\"propsString\""] ||
                             [rawString containsString:@"\"propsEvent\""] ||
                             [rawString containsString:@"\"popCount\""])) {
        return NO;
    }

    if ([object isKindOfClass:[NSDictionary class]]) {
        NSDictionary *rootDict = (NSDictionary *)object;
        NSInteger merchantSignals = 0;
        if (rootDict[@"image_link"]) merchantSignals++;
        if (rootDict[@"availability"]) merchantSignals++;
        if (rootDict[@"condition"]) merchantSignals++;
        if (rootDict[@"currency"]) merchantSignals++;
        if (rootDict[@"brand"]) merchantSignals++;
        if (merchantSignals >= 3) {
            return NO;
        }

        NSInteger trackingSignals = 0;
        if (rootDict[@"operation"]) trackingSignals++;
        if (rootDict[@"event_timestamp"]) trackingSignals++;
        if (rootDict[@"session_id"]) trackingSignals++;
        if (rootDict[@"device_id"]) trackingSignals++;
        if (rootDict[@"sdk_version"]) trackingSignals++;
        if (rootDict[@"advertising_id"]) trackingSignals++;
        if (trackingSignals >= 3) {
            return NO;
        }
    }

    return SHPFindMatchingPDPObject(object, shopID, itemID, 0) != nil;
}

- (void)submitCapturedJSONString:(NSString *)jsonString sourceURL:(NSString *)sourceURL {
    if (!jsonString.length || !self.currentTask || self.submittingCurrentTask) {
        return;
    }

    self.submittingCurrentTask = YES;
    NSString *submitURL = sourceURL.length ? sourceURL : self.currentTask.pdpURL;
    if (!submitURL.length) {
        submitURL = SHPBuildPDPURL(self.currentTask.shopID, self.currentTask.itemID);
    }

    self.pendingSubmitJSONString = [jsonString copy];
    self.pendingSubmitSourceURL = [submitURL copy];

    NSString *username = SHPStringValue(self.usernameField.text) ?: [self savedUsername] ?: @"";
    BOOL usingApi2 = self.apiType == 2;
    NSString *submitID = NSUUID.UUID.UUIDString;
    NSMutableDictionary *body = [NSMutableDictionary dictionary];
    [body setObject:(usingApi2 ? @"api2_submit_plain" : @"api1_submit") forKey:@"act"];
    [body setObject:@(usingApi2 ? 2 : 1) forKey:@"api_type"];
    [body setObject:kSHPSubmitAppVersion forKey:@"appVersion"];
    [body setObject:(submitURL ?: @"") forKey:@"url"];
    [body setObject:jsonString forKey:@"result"];
    [body setObject:jsonString forKey:@"data"];
    [body setObject:submitID forKey:@"submit_id"];
    if (usingApi2) {
        NSString *api2Group = self.groupID.length ? self.groupID : kSHPApi2FixedUsername;
        NSString *api2Number = [self api2Number];
        NSDictionary *taskData = SHPDictionaryValue(self.currentTask.rawPayload);
        NSDictionary *taskInfo = SHPDictionaryValue(taskData[@"Task"]);
        if (!taskInfo.count) {
            taskInfo = self.currentTask.traceID.length ? @{@"ID": self.currentTask.traceID} : @{};
        }
        [body setObject:(api2Number.length ? api2Number : kSHPApi2FixedUsername) forKey:@"username"];
        [body setObject:api2Group forKey:@"group_id"];
        [body setObject:taskInfo forKey:@"task_info"];
    } else if (username.length) {
        [body setObject:username forKey:@"username"];
    }
    if (self.deviceID.length) {
        [body setObject:self.deviceID forKey:@"device_id"];
        [body setObject:self.deviceID forKey:@"fingerprint_key"];
    }
    if (self.currentTask.traceID.length) {
        [body setObject:self.currentTask.traceID forKey:@"task_id"];
        [body setObject:self.currentTask.traceID forKey:@"trace_id"];
    }
    if (self.currentTask.itemID.length) {
        [body setObject:self.currentTask.itemID forKey:@"item_id"];
    }
    if (self.currentTask.shopID.length) {
        [body setObject:self.currentTask.shopID forKey:@"shop_id"];
    }
    if (self.currentTask.productURL.length) {
        [body setObject:self.currentTask.productURL forKey:@"product_url"];
    }
    if (self.currentTask.pdpURL.length) {
        [body setObject:self.currentTask.pdpURL forKey:@"pdp_url"];
    }
    if (self.token.length) {
        [body setObject:self.token forKey:@"auth_token"];
    }

    [self appendLog:[NSString stringWithFormat:@"提交中... %@", submitID]];
    [self sendJSONRequestToURL:kSHPControlURL method:@"POST" body:body authorized:YES completion:^(NSInteger statusCode, id jsonObject, NSData *data, NSError *error) {
        if (error) {
            [self appendLog:[NSString stringWithFormat:@"提交失败:%@", error.localizedDescription ?: @"未知"]];
            [self finishCurrentTaskAndContinueWithSuccess:NO reason:@"提交失败,跳过"];
            return;
        }

        [self appendLog:[NSString stringWithFormat:@"提交HTTP=%ld", (long)statusCode]];

        if (statusCode == 401) {
            self.token = nil;
            [self persistDefaults];
            [self refreshUI];
            [self appendLog:@"提交401,重登"];
            [self finishCurrentTaskAndContinueWithSuccess:NO reason:@"提交失败,跳过"];
            return;
        }

        if (statusCode < 200 || statusCode >= 300) {
            [self finishCurrentTaskAndContinueWithSuccess:NO reason:[NSString stringWithFormat:@"提交失败HTTP=%ld", (long)statusCode]];
            return;
        }

        NSDictionary *respDict = [jsonObject isKindOfClass:[NSDictionary class]] ? (NSDictionary *)jsonObject : nil;
        NSString *respCode = SHPStringValue(respDict[@"code"]);
        NSString *respMsg = SHPStringValue(respDict[@"msg"]) ?: SHPStringValue(respDict[@"message"]);
        NSDictionary *respData = SHPDictionaryValue(respDict[@"data"]);
        NSString *respDataCode = SHPStringValue(respData[@"code"]);
        NSString *respDataMsg = SHPStringValue(respData[@"msg"]);
        BOOL api2SubmitOK = usingApi2 && [self responseObjectAllowsAccess:jsonObject];
        if (usingApi2 && api2SubmitOK) {
            id okValue = respDict[@"ok"];
            if ([okValue respondsToSelector:@selector(boolValue)]) {
                api2SubmitOK = [okValue boolValue];
            } else if (respCode.length) {
                api2SubmitOK = [respCode isEqualToString:@"200"] || [respCode caseInsensitiveCompare:@"SUCCESS"] == NSOrderedSame;
            }
        }
        if (usingApi2 && !api2SubmitOK) {
            [self appendLog:[NSString stringWithFormat:@"接口2提交失败:%@", respMsg ?: respCode ?: @"unknown"]];
            [self finishCurrentTaskAndContinueWithSuccess:NO reason:nil];
            return;
        }
        NSDictionary *proxyInfo = SHPDictionaryValue(respDict[@"_proxy"]);
        BOOL proxyContextMatch = YES;
        if (proxyInfo.count) {
            id matchValue = proxyInfo[@"context_match"];
            if ([matchValue respondsToSelector:@selector(boolValue)]) {
                proxyContextMatch = [matchValue boolValue];
            }
        }
        if (proxyInfo.count && !proxyContextMatch) {
            NSString *proxySubmitID = SHPStringValue(proxyInfo[@"submit_id"]);
            NSString *proxyTaskID = SHPStringValue(proxyInfo[@"task_id"]);
            [self appendLog:[NSString stringWithFormat:@"提交回执不匹配 submit=%@ task=%@", proxySubmitID ?: @"-", proxyTaskID ?: @"-"]];
        }

        if (respCode.length && ![respCode isEqualToString:@"200"]) {
            [self appendLog:[NSString stringWithFormat:@"提交失败:%@", respMsg ?: respCode]];
            [self finishCurrentTaskAndContinueWithSuccess:NO reason:nil];
            return;
        }

        if (respDataCode.length && ![respDataCode isEqualToString:@"SUCCESS"]) {
            NSString *failureText = respDataMsg.length ? respDataMsg : respDataCode;
            [self appendLog:[NSString stringWithFormat:@"提交失败:%@", failureText]];
            [self finishCurrentTaskAndContinueWithSuccess:NO reason:nil];
            return;
        }

        if (respMsg.length) {
            NSString *lowerMsg = respMsg.lowercaseString;
            if ([lowerMsg containsString:@"不正确"] ||
                [lowerMsg containsString:@"失败"] ||
                [lowerMsg containsString:@"错误"] ||
                [lowerMsg containsString:@"invalid"] ||
                [lowerMsg containsString:@"fail"] ||
                [lowerMsg containsString:@"error"]) {
                [self appendLog:[NSString stringWithFormat:@"提交失败:%@", respMsg]];
                [self finishCurrentTaskAndContinueWithSuccess:NO reason:nil];
                return;
            }
        }

        if (respDataMsg.length) {
            NSString *lowerMsg = respDataMsg.lowercaseString;
            if ([lowerMsg containsString:@"不正确"] ||
                [lowerMsg containsString:@"失败"] ||
                [lowerMsg containsString:@"错误"] ||
                [lowerMsg containsString:@"invalid"] ||
                [lowerMsg containsString:@"fail"] ||
                [lowerMsg containsString:@"error"]) {
                [self appendLog:[NSString stringWithFormat:@"提交失败:%@", respDataMsg]];
                [self finishCurrentTaskAndContinueWithSuccess:NO reason:nil];
                return;
            }
        }

        [self appendLog:@"提交确认成功"];
        [self finishCurrentTaskAndContinueWithSuccess:YES reason:nil];
    }];
}

- (void)inspectCapturedData:(NSData *)data sourceURLString:(NSString *)urlString {
    if (!data.length || !urlString.length) {
        return;
    }

    if (![urlString containsString:@"/api/v4/pdp/"]) {
        return;
    }

    id jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (!jsonObject || ![jsonObject isKindOfClass:[NSDictionary class]]) {
        return;
    }

    NSString *jsonString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!jsonString.length) {
        jsonString = SHPJSONStringFromObject(jsonObject);
    }

    NSDictionary *jsonDict = (NSDictionary *)jsonObject;

    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self.currentTask || self.submittingCurrentTask || !self.waitingForPDP) {
            return;
        }

        id matchedPDPObject = SHPFindMatchingPDPObject(jsonObject, self.currentTask.shopID, self.currentTask.itemID, 0);
        if (!matchedPDPObject) {
            NSDictionary *mainIDs = SHPExtractPDPMainIDs(jsonObject);
            NSString *foundItem = mainIDs[@"item_id"];
            NSString *foundShop = mainIDs[@"shop_id"];
            [self appendLog:[NSString stringWithFormat:@"PDP涓诲晢鍝佷笉鍖归厤 %@/%@", foundShop ?: @"-", foundItem ?: @"-"]];
            return;
        }
        if (matchedPDPObject != jsonObject) {
            NSString *matchedJSONString = SHPJSONStringFromObject(matchedPDPObject);
            if (matchedJSONString.length) {
                jsonString = matchedJSONString;
            }
        }

        if (matchedPDPObject == jsonObject && jsonString.length < 10240) {
            NSInteger errorCode = 0;
            NSNumber *errorVal = jsonDict[@"error"];
            if ([errorVal isKindOfClass:[NSNumber class]]) {
                errorCode = errorVal.integerValue;
            }
            [self appendLog:[NSString stringWithFormat:@"数据不完整 error=%ld,继续等待...", (long)errorCode]];

            NSString *currentItemID = self.currentTask.itemID;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (!self.waitingForPDP || !self.currentTask) {
                    return;
                }
                if (currentItemID.length && ![self.currentTask.itemID isEqualToString:currentItemID]) {
                    return;
                }
                self.waitingForPDP = NO;
                NSString *reason = [NSString stringWithFormat:@"获取数据异常 error=%ld", (long)errorCode];
                if ([self handleNoDataCaptureWithMessage:reason currentItemID:currentItemID]) {
                    return;
                }
            });
            return;
        }

        self.consecutivePDPFailures = 0;
        self.waitingForPDP = NO;
        [self appendLog:@"获取到数据,提交"];
        [self submitCapturedJSONString:jsonString sourceURL:urlString];
    });
}

- (void)inspectResponseData:(NSData *)data response:(NSURLResponse *)response request:(NSURLRequest *)request error:(NSError *)error {
    if (error || !data.length || !self.currentTask || self.submittingCurrentTask) {
        return;
    }

    NSString *urlString = response.URL.absoluteString ?: request.URL.absoluteString;
    [self inspectCapturedData:data sourceURLString:urlString];
}

- (void)inspectParsedJSONObject:(id)object rawData:(NSData *)rawData {
    if (!self.currentTask || self.submittingCurrentTask || !self.waitingForPDP || rawData.length < 10240) {
        return;
    }

    NSString *shopID = self.currentTask.shopID;
    NSString *itemID = self.currentTask.itemID;
    id matchedPDPObject = SHPFindMatchingPDPObject(object, shopID, itemID, 0);
    if (!matchedPDPObject) {
        return;
    }

    NSString *jsonString = SHPJSONStringFromObject(matchedPDPObject);
    if (!jsonString.length && rawData.length) {
        jsonString = [[NSString alloc] initWithData:rawData encoding:NSUTF8StringEncoding];
    }

    if (jsonString.length) {
        [self appendLog:@"获取到数据,提交"];
        self.consecutivePDPFailures = 0;
        self.waitingForPDP = NO;
        [self submitCapturedJSONString:jsonString sourceURL:self.currentTask.pdpURL];
    }
}

- (void)handleRiskControlDetected {
    [self handleRiskControlDetectedWithMessage:@"检测到风控，已自动停止"];
}

- (void)handleRiskControlDetectedWithMessage:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.isRiskControlled) {
            return;
        }
        self.isRiskControlled = YES;

        self.isRunning = NO;
        self.requestInFlight = NO;
        self.submittingCurrentTask = NO;
        self.waitingForPDP = NO;
        [self.pollTimer invalidate];
        self.pollTimer = nil;
        self.nextFireDate = nil;
        [self stopCountdownTimer];
        [self stopHeartbeat];
        self.currentTask = nil;
        [self clearPendingSubmissionState];
        [self persistDefaults];

        [self appendLog:message.length ? message : @"检测到风控，已自动停止"];
        [self refreshUI];
    });
}

@end

static char kSHPBufferKey;

static void SHPDidReceiveDataHook(id self, SEL _cmd, id module, id requestLike, id dataObject) {
    IMP origIMP = SHPOriginalIMPForClass(SHPOriginalDidReceiveDataIMPMap, object_getClass(self));
    if (origIMP) {
        ((void (*)(id, SEL, id, id, id))origIMP)(self, _cmd, module, requestLike, dataObject);
    }

    if (![dataObject isKindOfClass:[NSData class]] || !requestLike) {
        return;
    }

    @try {
        NSMutableData *buffer = objc_getAssociatedObject(requestLike, &kSHPBufferKey);
        if (!buffer) {
            buffer = [NSMutableData data];
            objc_setAssociatedObject(requestLike, &kSHPBufferKey, buffer, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        [buffer appendData:(NSData *)dataObject];
    } @catch (__unused NSException *exception) {}
}

static void SHPDidCompleteWithErrorHook(id self, SEL _cmd, id module, id requestLike, id errorObject) {
    IMP origIMP = SHPOriginalIMPForClass(SHPOriginalDidCompleteIMPMap, object_getClass(self));
    if (origIMP) {
        ((void (*)(id, SEL, id, id, id))origIMP)(self, _cmd, module, requestLike, errorObject);
    }

    if (errorObject && errorObject != [NSNull null]) {
        return;
    }

    @try {
        NSData *completeData = nil;

        NSMutableData *buffer = objc_getAssociatedObject(requestLike, &kSHPBufferKey);
        if (buffer.length) {
            completeData = [buffer copy];
            objc_setAssociatedObject(requestLike, &kSHPBufferKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }

        if (!completeData.length) {
            NSArray<NSString *> *dataSelectors = @[@"responseData", @"data", @"rawData", @"bodyData"];
            for (NSString *selectorName in dataSelectors) {
                id dataValue = SHPCallNoArgObject(requestLike, selectorName);
                if ([dataValue isKindOfClass:[NSData class]] && [(NSData *)dataValue length] > 0) {
                    completeData = (NSData *)dataValue;
                    break;
                }
            }
        }

        if (completeData.length) {
            [[SHPPluginController shared] inspectCapturedData:completeData sourceURLString:SHPURLStringFromRequestLikeObject(requestLike)];
        }
    } @catch (__unused NSException *exception) {}
}

static void SHPInstallShopeeSpecificHooks(void) {
    SHPOriginalDidReceiveDataIMPMap = [NSMutableDictionary dictionary];
    SHPOriginalDidCompleteIMPMap = [NSMutableDictionary dictionary];

    SEL receiveSelector = NSSelectorFromString(@"shpNetworkingModule:shpRequest:didReceiveData:");
    SEL completeSelector = NSSelectorFromString(@"shpNetworkingModule:shpRequest:didCompleteWithError:");

    int classCount = objc_getClassList(NULL, 0);
    if (classCount <= 0) {
        return;
    }

    Class *classes = (Class *)calloc((size_t)classCount, sizeof(Class));
    classCount = objc_getClassList(classes, classCount);

    for (int index = 0; index < classCount; index++) {
        @try {
            Class cls = classes[index];
            if (!cls) {
                continue;
            }
            NSString *className = NSStringFromClass(cls);
            if (!className.length) {
                continue;
            }

            Method receiveMethod = class_getInstanceMethod(cls, receiveSelector);
            if (SHPMethodHasVoidReturnAndObjectArguments(receiveMethod, 3)) {
                IMP oldIMP = NULL;
                MSHookMessageEx(cls, receiveSelector, (IMP)&SHPDidReceiveDataHook, &oldIMP);
                if (oldIMP) {
                    SHPOriginalDidReceiveDataIMPMap[className] = [NSValue valueWithPointer:(const void *)oldIMP];
                }
            }

            Method completeMethod = class_getInstanceMethod(cls, completeSelector);
            if (SHPMethodHasVoidReturnAndObjectArguments(completeMethod, 3)) {
                IMP oldIMP = NULL;
                MSHookMessageEx(cls, completeSelector, (IMP)&SHPDidCompleteWithErrorHook, &oldIMP);
                if (oldIMP) {
                    SHPOriginalDidCompleteIMPMap[className] = [NSValue valueWithPointer:(const void *)oldIMP];
                }
            }
        } @catch (__unused NSException *exception) {
            continue;
        }
    }

    free(classes);
}

static NSURLSession *SHPSessionWithConfigDelegateHook(id self, SEL _cmd, NSURLSessionConfiguration *config, id delegate, NSOperationQueue *queue) {
    NSURLSession *session = ((NSURLSession *(*)(id, SEL, id, id, id))SHPOriginalSessionWithConfigDelegateIMP)(self, _cmd, config, delegate, queue);

    if (!delegate) {
        return session;
    }

    @try {
        Class delegateClass = [delegate class];
        NSString *className = NSStringFromClass(delegateClass);
        if (!className.length || SHPOriginalDidReceiveDataIMPMap[className]) {
            return session;
        }

        SEL receiveSel = NSSelectorFromString(@"shpNetworkingModule:shpRequest:didReceiveData:");
        SEL completeSel = NSSelectorFromString(@"shpNetworkingModule:shpRequest:didCompleteWithError:");

        if (![delegate respondsToSelector:receiveSel]) {
            receiveSel = @selector(URLSession:dataTask:didReceiveData:);
            completeSel = @selector(URLSession:task:didCompleteWithError:);
        }

        if ([delegate respondsToSelector:receiveSel]) {
            IMP oldIMP = NULL;
            MSHookMessageEx(delegateClass, receiveSel, (IMP)&SHPDidReceiveDataHook, &oldIMP);
            if (oldIMP) {
                SHPOriginalDidReceiveDataIMPMap[className] = [NSValue valueWithPointer:(const void *)oldIMP];
            }
        }

        if ([delegate respondsToSelector:completeSel]) {
            IMP oldIMP = NULL;
            MSHookMessageEx(delegateClass, completeSel, (IMP)&SHPDidCompleteWithErrorHook, &oldIMP);
            if (oldIMP) {
                SHPOriginalDidCompleteIMPMap[className] = [NSValue valueWithPointer:(const void *)oldIMP];
            }
        }
    } @catch (__unused NSException *e) {}

    return session;
}

%ctor {
    @autoreleasepool {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        if (![bundleID isEqualToString:kSHPBundleID]) {
            return;
        }

        SHPOriginalDidReceiveDataIMPMap = [NSMutableDictionary dictionary];
        SHPOriginalDidCompleteIMPMap = [NSMutableDictionary dictionary];

        @try {
            Class sessionClass = objc_getClass("NSURLSession");
            if (sessionClass) {
                MSHookMessageEx(object_getClass(sessionClass), @selector(sessionWithConfiguration:delegate:delegateQueue:), (IMP)&SHPSessionWithConfigDelegateHook, &SHPOriginalSessionWithConfigDelegateIMP);
            }
        } @catch (__unused NSException *e) {}

        dispatch_async(dispatch_get_main_queue(), ^{
            [[SHPPluginController shared] start];
        });
    }
}
