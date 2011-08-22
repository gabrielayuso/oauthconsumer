//
//  OAToken_KeychainExtensions.m
//  TouchTheFireEagle
//
//  Created by Jonathan Wight on 04/04/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import "OAToken_KeychainExtensions.h"

@implementation OAToken (OAToken_KeychainExtensions)

- (id)initWithKeychainUsingAppName:(NSString *)name serviceProviderName:(NSString *)provider 
{
    [super init];
    SecKeychainItemRef item;
	NSString *serviceName = [NSString stringWithFormat:@"%@::OAuth::%@", name, provider];
	OSStatus status = SecKeychainFindGenericPassword(NULL,
													 (unsigned int)strlen([serviceName UTF8String]),
													 [serviceName UTF8String],
													 0,
													 NULL,
													 NULL,
													 NULL,
													 &item);
    if (status != noErr) {
        return nil;
    }
    
    // from Advanced Mac OS X Programming, ch. 16
    UInt32 length;
    char *password;
    SecKeychainAttribute attribs[8];
    SecKeychainAttributeList list;
	
    attribs[0].tag = kSecAccountItemAttr;
    attribs[1].tag = kSecDescriptionItemAttr;
    attribs[2].tag = kSecLabelItemAttr;
    attribs[3].tag = kSecModDateItemAttr;
    
    list.count = 4;
    list.attr  = attribs;
    
    status = SecKeychainItemCopyContent(item, NULL, &list, &length, (void **)&password);
    
    if (status == noErr) {
		char* keyBuffer = malloc(sizeof(char)*(list.attr[0].length+1));
		
		strncpy(keyBuffer, list.attr[0].data, list.attr[0].length);
		keyBuffer[list.attr[0].length] = '\0';
		
        self.key = [NSString stringWithCString:keyBuffer encoding:NSUTF8StringEncoding];
		free(keyBuffer);
		
        if (password != NULL) {
            char passwordBuffer[1024];
            
            if (length > 1023) {
                length = 1023;
            }
            strncpy(passwordBuffer, password, length);
            
            passwordBuffer[length] = '\0';
			self.secret = [NSString stringWithCString:passwordBuffer encoding:NSUTF8StringEncoding];
        }
        
        SecKeychainItemFreeContent(&list, password);
        
    } else {
		// TODO find out why this always works in i386 and always fails on ppc
		NSLog(@"Error from SecKeychainItemCopyContent: %d", status);
        return nil;
    }
    
    NSMakeCollectable(item);
    
    return self;
}


- (int)storeInDefaultKeychainWithAppName:(NSString *)name serviceProviderName:(NSString *)provider 
{
    return [self storeInKeychain:NULL appName:name serviceProviderName:provider];
}

- (int)storeInKeychain:(SecKeychainRef)keychain appName:(NSString *)name serviceProviderName:(NSString *)provider 
{
	OSStatus status = SecKeychainAddGenericPassword(keychain,                                     
                                                    (unsigned int)([name length] + [provider length] + 9), 
                                                    [[NSString stringWithFormat:@"%@::OAuth::%@", name, provider] UTF8String],
                                                    (unsigned int)[self.key length],                        
                                                    [self.key UTF8String],
                                                    (unsigned int)[self.secret length],
                                                    [self.secret UTF8String],
                                                    NULL
                                                    );
	return status;
}

@end