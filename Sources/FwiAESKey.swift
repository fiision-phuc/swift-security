//  Project name: FwiSecurity
//  File name   : FwiAESKey.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 5/9/16
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
/// Optional
import FwiCore


public struct FwiAESKey {
   
    // MARK: Class's constructors
    public init(withIdentifier i: String? = String.randomIdentifier()) {
        key = FwiKey(withIdentifier: i)
        if key.entry == nil {
            key.attributes[SecAttr.type.value] = UInt32(integerLiteral: 2147483649)
            key.attributes[SecAttr.decr.value] = kCFBooleanTrue
            key.attributes[SecAttr.encr.value] = kCFBooleanTrue
        }
    }
    public init(withIdentifier i: String? = String.randomIdentifier(), keySize s: FwiAESSize) {
        self.init(withIdentifier: i)
        
        // Generate data
        var keyBytes = [UInt8](repeating: 0, count: s.length)
        defer { bzero(&keyBytes, s.length) }
    
        // Random bytes
        _ = SecRandomCopyBytes(kSecRandomDefault, s.length, &keyBytes)
    
        // Save key's data
        let data = Data(bytesNoCopy: &keyBytes, count: s.length, deallocator: .none)
        key.save(withData: data)
    }
    
    // MARK: Class's properties
    public var iv: Data?
    public var inKeystore: Bool {
        return key.entry != nil
    }
    
    fileprivate var key: FwiKey
    
    // MARK: Class's public methods
    /// Encrypt Data.
    ///
    /// - parameter data (required): data to be encrypted
    public mutating func encrypt(data d: Data?, enableIV useIV: Bool = false) -> Data? {
        /* Condition validation */
        guard let data = d, data.count > 0 else {
            return nil
        }
        
        let operation = CCOperation(kCCEncrypt)
        let algorithm = CCAlgorithm(kCCAlgorithmAES128)
        let option = CCOptions(kCCOptionECBMode + kCCOptionPKCS7Padding)
        
        // Generate IV
        if useIV {
            var bytes = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
            _ = SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, &bytes)
            
            iv = Data(bytes: bytes)
        }
        
        // Create crypto
        var input = data.bytes()
        var ivData = iv?.bytes() ?? []
        var keyData = key.encode()?.bytes() ?? []
        defer {
            bzero(&input, input.count)
            bzero(&ivData, ivData.count)
            bzero(&keyData, keyData.count)
        }
        
        // Encrypt process
        var length = (data.count / kCCBlockSizeAES128 + 1) * kCCBlockSizeAES128
        var output = [UInt8](repeating: 0, count: length)
        
        let status = CCCrypt(operation, algorithm, option,
                             keyData, keyData.count, ivData,
                             input, input.count,
                             &output, length, &length)

        guard status == CCCryptorStatus(kCCSuccess) else {
            return nil
        }
        return Data(bytes: &output, count: length)
    }
    
    /// Decrypt Data.
    ///
    /// - parameter data (required): data to be decrypted
    public mutating func decrypt(data d: Data?) -> Data? {
        /* Condition validation */
        guard let data = d, data.count % kCCBlockSizeAES128 == 0 else {
            return nil
        }
        
        let operation = CCOperation(kCCDecrypt)
        let algorithm = CCAlgorithm(kCCAlgorithmAES128)
        let option = CCOptions(kCCOptionECBMode + kCCOptionPKCS7Padding)
        
        // Create crypto
        var input = data.bytes()
        var ivData = iv?.bytes() ?? []
        var keyData = key.encode()?.bytes() ?? []
        defer {
            bzero(&input, input.count)
            bzero(&ivData, ivData.count)
            bzero(&keyData, keyData.count)
        }
        
        // Decrypt process
        var length = data.count
        var output = [UInt8](repeating: 0, count: length)
        let status = CCCrypt(operation, algorithm, option,
                             keyData, keyData.count, ivData,
                             input, input.count,
                             &output, length, &length)
//        CCCrypt(_ op: CCOperation,
//                _ alg: CCAlgorithm,
//                _ options: CCOptions,
//                _ key: UnsafeRawPointer!,
//                _ keyLength: Int,
//                _ iv: UnsafeRawPointer!,
//                _ dataIn: UnsafeRawPointer!,
//                _ dataInLength: Int,
//                _ dataOut: UnsafeMutableRawPointer!,
//                _ dataOutAvailable: Int,
//                _ dataOutMoved: UnsafeMutablePointer<Int>!)
        guard status == CCCryptorStatus(kCCSuccess) else {
            return nil
        }
        return Data(bytes: &output, count: length)
    }
    
    /// Remove current key from keystore.
    public func remove() {
        key.remove()
    }
    
    /// Convert to raw data.
    public func encode() -> Data? {
        return key.encode()
    }
    
    /// Convert raw data to base64 data.
    internal func encodeBase64Data() -> Data? {
        return key.encodeBase64Data()
    }
    
    /// Convert raw data to base64 string.
    internal func encodeBase64String() -> String? {
        return key.encodeBase64String()
    }
}
