//  Project name: FwiSecurity
//  File name   : FwiSecurity.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 12/6/16
//  Version     : 1.00
//  --------------------------------------------------------------
//  Copyright © 2012, 2017 Fiision Studio.
//  All Rights Reserved.
//  --------------------------------------------------------------
//
//  Permission is hereby granted, free of charge, to any person obtaining  a  copy
//  of this software and associated documentation files (the "Software"), to  deal
//  in the Software without restriction, including without limitation  the  rights
//  to use, copy, modify, merge,  publish,  distribute,  sublicense,  and/or  sell
//  copies of the Software,  and  to  permit  persons  to  whom  the  Software  is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF  ANY  KIND,  EXPRESS  OR
//  IMPLIED, INCLUDING BUT NOT  LIMITED  TO  THE  WARRANTIES  OF  MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO  EVENT  SHALL  THE
//  AUTHORS OR COPYRIGHT HOLDERS  BE  LIABLE  FOR  ANY  CLAIM,  DAMAGES  OR  OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING  FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN  THE
//  SOFTWARE.
//
//
//  Disclaimer
//  __________
//  Although reasonable care has been taken to  ensure  the  correctness  of  this
//  software, this software should never be used in any application without proper
//  testing. Fiision Studio disclaim  all  liability  and  responsibility  to  any
//  person or entity with respect to any loss or damage caused, or alleged  to  be
//  caused, directly or indirectly, by the use of this software.

import CommonCrypto
import Foundation


/// AES key size supported.
public enum FwiAES {
    case size128            // 16 bytes
    case size192            // 24 bytes
    case size256            // 32 bytes
    
    var value: Int {
        switch self {
            
        case .size192:
            return kCCKeySizeAES192
            
        case .size256:
            return kCCKeySizeAES256
            
        default:
            return kCCKeySizeAES128
        }
    }
}

/// RSA key size supported.
public enum FwiRSA: Int16 {
    case size1024 = 1024    // 128 bytes
    case size2048 = 2048    // 256 bytes
    case size4096 = 4096    // 512 bytes
}

//typedef NS_ENUM(NSInteger, FwiDigest) {
//    kSHA1   = CC_SHA1_DIGEST_LENGTH,    // 20 bytes     iOS 5
//    kSHA256 = CC_SHA256_DIGEST_LENGTH,  // 32 bytes     iOS 6
//    kSHA384 = CC_SHA384_DIGEST_LENGTH,  // 48 bytes     ?????
//    kSHA512 = CC_SHA512_DIGEST_LENGTH   // 64 bytes     iOS 5
//};  // Digest supported
//
//typedef NS_ENUM(NSInteger, FwiHmacHash) {
//    kHmacHash_1   = kCCHmacAlgSHA1,     // 20 bytes
//    kHmacHash_256 = kCCHmacAlgSHA256,   // 32 bytes
//    kHmacHash_384 = kCCHmacAlgSHA384,   // 48 bytes
//    kHmacHash_512 = kCCHmacAlgSHA512    // 64 bytes
//};  // HmacHash supported
