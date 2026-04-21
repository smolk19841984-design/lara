filepath = r'C:\Users\smolk\Documents\2\lara-main\jbdc\remote\LaraMobAIServer.m'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add darksword.h import
old_import = '#import "../kexploit/term.h"'
new_import = '#import "../kexploit/term.h"\n#import "../kexploit/darksword.h"'
content = content.replace(old_import, new_import)

# 2. Add route registration
old_routes = (
    '            if ([route isEqualToString:@"scroll"]) return [self handleMobAIScroll:body];\n'
    '        }\n'
    '    }\n'
    '\n'
    '    return [self httpResponse:404 body:@"{\\"error\\":\\"Not Found\\"}"];'
)
new_routes = (
    '            if ([route isEqualToString:@"scroll"]) return [self handleMobAIScroll:body];\n'
    '            if ([route isEqualToString:@"kread"]) return [self handleMobAIKRead:body];\n'
    '            if ([route isEqualToString:@"kwrite"]) return [self handleMobAIKWrite:body];\n'
    '        }\n'
    '    }\n'
    '\n'
    '    return [self httpResponse:404 body:@"{\\"error\\":\\"Not Found\\"}"];'
)
content = content.replace(old_routes, new_routes)

# 3. Add handler methods before @end
old_end = '@end'
new_handlers = '''- (NSString *)handleMobAIKRead:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\\"error\\":\\"Invalid JSON\\"}"];
    NSString *addrStr = json[@"address"] ?: json[@"addr"] ?: @"";
    if (addrStr.length == 0) return [self httpResponse:400 body:@"{\\"error\\":\\"Missing address\\"}"];

    uint64_t addr = 0;
    if ([addrStr hasPrefix:@"0x"] || [addrStr hasPrefix:@"0X"]) {
        NSScanner *scanner = [NSScanner scannerWithString:addrStr];
        unsigned long long val = 0;
        [scanner scanHexLongLong:&val];
        addr = (uint64_t)val;
    } else {
        addr = (uint64_t)[addrStr longLongValue];
    }
    if (addr == 0) return [self httpResponse:400 body:@"{\\"error\\":\\"Invalid address\\"}"];

    uint64_t value = ds_kread64(addr);
    NSString *jsonResp = [NSString stringWithFormat:@"{\\"address\\":\\"0x%%016llx\\",\\"value\\":\\"0x%%016llx\\",\\"value_dec\\":\\"%%llu\\"}", addr, value, value];
    return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
}

- (NSString *)handleMobAIKWrite:(NSString *)body {
    NSDictionary *json = [self parseJSON:body];
    if (!json) return [self httpResponse:400 body:@"{\\"error\\":\\"Invalid JSON\\"}"];
    NSString *addrStr = json[@"address"] ?: json[@"addr"] ?: @"";
    NSString *valStr = json[@"value"] ?: @"";
    if (addrStr.length == 0 || valStr.length == 0) return [self httpResponse:400 body:@"{\\"error\\":\\"Missing address or value\\"}"];

    uint64_t addr = 0, val = 0;
    if ([addrStr hasPrefix:@"0x"] || [addrStr hasPrefix:@"0X"]) {
        NSScanner *scanner = [NSScanner scannerWithString:addrStr];
        unsigned long long v = 0;
        [scanner scanHexLongLong:&v];
        addr = (uint64_t)v;
    } else {
        addr = (uint64_t)[addrStr longLongValue];
    }
    if ([valStr hasPrefix:@"0x"] || [valStr hasPrefix:@"0X"]) {
        NSScanner *scanner = [NSScanner scannerWithString:valStr];
        unsigned long long v = 0;
        [scanner scanHexLongLong:&v];
        val = (uint64_t)v;
    } else {
        val = (uint64_t)[valStr longLongValue];
    }
    if (addr == 0) return [self httpResponse:400 body:@"{\\"error\\":\\"Invalid address\\"}"];

    ds_kwrite64(addr, val);
    uint64_t verify = ds_kread64(addr);
    NSString *jsonResp = [NSString stringWithFormat:@"{\\"address\\":\\"0x%%016llx\\",\\"written\\":\\"0x%%016llx\\",\\"verified\\":\\"0x%%016llx\\",\\"match\\":%%@}", addr, val, verify, (verify == val) ? @"true" : @"false"];
    return [self httpResponse:200 contentType:@"application/json" body:jsonResp];
}

@end'''
content = content.replace(old_end, new_handlers)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print('kread/kwrite endpoints added to LaraMobAIServer.m')
