//
//  Keepalive.m
//  lara
//
//  Rewritten in Objective-C (was keepalive.swift)
//

#import <AVFoundation/AVFoundation.h>
#import "Keepalive.h"
#import "../Logger.h"

static NSURL *getwavurl(void);
static void makesilentwav(NSURL *url);

static AVAudioPlayer *s_player = nil;
static BOOL s_kaEnabled = NO;

BOOL kaenabled(void) {
    return s_kaEnabled;
}

void toggleka(void) {
    if (s_kaEnabled) {
        [s_player stop];
        s_player = nil;
        s_kaEnabled = NO;
        [[Logger shared] log:@"(ka) disabled keepalive"];
        return;
    }

    NSError *err;
    AVAudioSession *session = [AVAudioSession sharedInstance];
    if (![session setCategory:AVAudioSessionCategoryPlayback
                         mode:AVAudioSessionModeDefault
                      options:AVAudioSessionCategoryOptionMixWithOthers
                        error:&err]) {
        [[Logger shared] log:[NSString stringWithFormat:@"(ka) audio session category failed: %@", err.localizedDescription]];
        return;
    }
    if (![session setActive:YES error:&err]) {
        [[Logger shared] log:[NSString stringWithFormat:@"(ka) audio session activate failed: %@", err.localizedDescription]];
        return;
    }

    NSURL *fileURL = getwavurl();
    if (![[NSFileManager defaultManager] fileExistsAtPath:fileURL.path]) {
        makesilentwav(fileURL);
    }

    s_player = [[AVAudioPlayer alloc] initWithContentsOfURL:fileURL error:&err];
    if (!s_player) {
        [[Logger shared] log:[NSString stringWithFormat:@"(ka) audio init failed: %@", err.localizedDescription]];
        return;
    }

    s_player.numberOfLoops = -1;
    s_player.volume = 0.0f;
    [s_player prepareToPlay];
    [s_player play];
    s_kaEnabled = YES;
    [[Logger shared] log:@"(ka) enabled keepalive"];
}

static NSURL *getwavurl(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [NSURL fileURLWithPath:[docs stringByAppendingPathComponent:@"silent.wav"]];
}

static void makesilentwav(NSURL *url) {
    int sampleRate = 44100;
    int duration = 1;
    int numSamples = sampleRate * duration;
    int byteRate = sampleRate * 2;
    uint16_t blockAlign = 2;
    int dataSize = numSamples * 2;
    int chunkSize = 36 + dataSize;

    NSMutableData *wav = [NSMutableData data];

    [wav appendData:[@"RIFF" dataUsingEncoding:NSASCIIStringEncoding]];
    uint32_t v32 = (uint32_t)chunkSize; [wav appendBytes:&v32 length:4];
    [wav appendData:[@"WAVE" dataUsingEncoding:NSASCIIStringEncoding]];
    [wav appendData:[@"fmt " dataUsingEncoding:NSASCIIStringEncoding]];
    v32 = 16; [wav appendBytes:&v32 length:4];
    uint16_t v16 = 1; [wav appendBytes:&v16 length:2];
    v16 = 1;         [wav appendBytes:&v16 length:2];
    v32 = (uint32_t)sampleRate; [wav appendBytes:&v32 length:4];
    v32 = (uint32_t)byteRate;   [wav appendBytes:&v32 length:4];
    [wav appendBytes:&blockAlign length:2];
    v16 = 16; [wav appendBytes:&v16 length:2];
    [wav appendData:[@"data" dataUsingEncoding:NSASCIIStringEncoding]];
    v32 = (uint32_t)dataSize; [wav appendBytes:&v32 length:4];
    [wav appendData:[NSMutableData dataWithLength:dataSize]];

    [wav writeToURL:url atomically:YES];
}
