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
        inBuffer  = [UInt8](repeating: 0, count: buffer)
        outBuffer = [UInt8](repeating: 0, count: buffer)
        
        key = FwiKey(withIdentifier: i)
        key.attributes[SecAttr.type.value] = 2147483649
        key.attributes[SecAttr.decr.value] = kCFBooleanTrue
        key.attributes[SecAttr.encr.value] = kCFBooleanTrue
    }
    public init(withSize s: FwiAESSize, identifier i: String? = String.randomIdentifier()) {
        self.init(withIdentifier: i)
    }
    
    // MARK: Class's properties
    public var iv: Data?   // Initialization vector
    
    fileprivate var key: FwiKey
    fileprivate let buffer = 128
    fileprivate var inBuffer: [UInt8]
    fileprivate var outBuffer: [UInt8]
    
    
//    internal var entry: Data? {
//        return Keychain.load(identifier)
//    }
    
    // MARK: Class's public methods
//    /** Check Value Save In KeyChain */
//    func inKeystore() -> Bool {
//        return entry != nil
//    }
    
     /** Encrypt Data */
    func encryptData(_ dataEncrypt: Data) -> Data? {
//        cipherLen = (clearLen/16 + 1) * 16;
        
//        guard inKeystore() else {
//            return nil
//        }
        
        
        if dataEncrypt.count == 0 {return nil}
//        guard let keyData = entry else {
//            return nil
//        }
//        
//        let keyBytes = UnsafeMutableRawPointer(mutating: (keyData as NSData).bytes.bindMemory(to: Void.self, capacity: keyData.count))
//    
//        let dataLength = size_t(dataEncrypt.count)
//        let dataBytes = UnsafeMutableRawPointer(mutating: (dataEncrypt as NSData).bytes.bindMemory(to: Void.self, capacity: dataEncrypt.count))
//        
//        let cryptData = NSMutableData(length: Int(dataLength) + kCCBlockSizeAES128)
//        let cryptPointer = UnsafeMutableRawPointer(cryptData!.mutableBytes)
//        let cryptLength = size_t(cryptData!.length)
//        
//        let keyLength = size_t(kCCKeySizeAES128)
//        let operation: CCOperation = UInt32(kCCEncrypt)
//        let algoritm: CCAlgorithm = UInt32(kCCAlgorithmAES128)
//        let options: CCOptions   = UInt32(kCCOptionPKCS7Padding + kCCOptionECBMode)
//        
//        var numBytesEncrypted :size_t = 0
//        
//        let cryptStatus = CCCrypt(operation,
//                                  algoritm,
//                                  options,
//                                  keyBytes, keyLength,
//                                  nil,
//                                  dataBytes, dataLength,
//                                  cryptPointer, cryptLength,
//                                  &numBytesEncrypted)
//        
//        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
//            cryptData!.length = Int(numBytesEncrypted)
//            return Data.init(referencing: cryptData!)
//            
//        } else {
//            print("Error: \(cryptStatus)")
//        }
        return nil
    }
    
     /** Decrypt Data */
    func decryptData(_ dataDecrypt: Data) -> Data? {
//        Data(capacity: 10)
//        CCCrypt(CCOperation(kCCDecrypt),
//                FwiAESSize.size128.algorithm,
//                CCOptions(kCCOptionPKCS7Padding),
//                key, FwiAESSize.size128.length,
//                iv,
//                <#T##dataIn: UnsafeRawPointer!##UnsafeRawPointer!#>, <#T##dataInLength: Int##Int#>, <#T##dataOut: UnsafeMutableRawPointer!##UnsafeMutableRawPointer!#>, <#T##dataOutAvailable: Int##Int#>, <#T##dataOutMoved: UnsafeMutablePointer<Int>!##UnsafeMutablePointer<Int>!#>)
        
        // Create decryptor
        var cryptoRef: CCCryptorRef?
        defer { cryptoRef = nil }
//
//        CCCryptorCreate(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding), key, kCCKeySizeAES256, nil, &cryptoRef)
//        
//        // Define buffer
//
//        // Decrypt process
//        var len = 0
//        var finalData = Data()
//        for index in stride(from: 0, to: data.count, by: bufferSize) {
//            var upper = index + bufferSize
//            upper = min(upper, data.count)
//            data.copyBytes(to: &inBuffer, from: Range<Data.Index>(uncheckedBounds: (lower: index, upper: upper)))
//            
//            let status = CCCryptorUpdate(cryptoRef, inBuffer, bufferSize, &outBuffer, bufferSize, &len)
//            guard Int(status) == kCCSuccess else {
//                preconditionFailure("Could not parse 'Ba-Prefix.plist'.")
//            }
//            finalData.append(outBuffer, count: len)
//        }
//        
//        let status = CCCryptorFinal(cryptoRef, &outBuffer, bufferSize, &len)
//        guard Int(status) == kCCSuccess else {
//            preconditionFailure("Could not parse 'Ba-Prefix.plist'.")
//        }
//        finalData.append(outBuffer, count: len)
        
        // ----- Old -------------------------------------------------------------------------------
//        guard self.inKeystore() else {
//            return nil
//        }
//        
//        guard inKeystore() else {
//            return nil
//        }
//        
//        if dataDecrypt.count == 0 {return nil}
//        
//        guard let keyData = entry else {
//            return nil
//        }
//        
//        let keyBytes = UnsafeMutableRawPointer(mutating: (keyData as NSData).bytes.bindMemory(to: Void.self, capacity: keyData.count))
//        
//        let dataLength = size_t(dataDecrypt.count)
//        let dataBytes = UnsafeMutableRawPointer(mutating: (dataDecrypt as NSData).bytes.bindMemory(to: Void.self, capacity: dataDecrypt.count))
//        
//        let cryptData = NSMutableData(length: Int(dataLength) + kCCBlockSizeAES128)
//        let cryptPointer = UnsafeMutableRawPointer(cryptData!.mutableBytes)
//        let cryptLength = size_t(cryptData!.length)
//        
//        let keyLength = size_t(kCCKeySizeAES128)
//        let operation: CCOperation = UInt32(kCCDecrypt)
//        let algoritm: CCAlgorithm = UInt32(kCCAlgorithmAES128)
//        let options: CCOptions   = UInt32(kCCOptionPKCS7Padding + kCCOptionECBMode)
//        
//        var numBytesEncrypted :size_t = 0
//        
//        let cryptStatus = CCCrypt(operation,
//                                  algoritm,
//                                  options,
//                                  keyBytes, keyLength,
//                                  nil,
//                                  dataBytes, dataLength,
//                                  cryptPointer, cryptLength,
//                                  &numBytesEncrypted)
//        
//        if cryptStatus == Int32(kCCSuccess) {
//            cryptData!.length = Int(numBytesEncrypted)
//            return Data.init(referencing: cryptData!)
//        } else {
//            print("Error: \(cryptStatus)")
//        }
        
        return nil
    }
    
    public func clear(){
//        Keychain.clear()
    }
}


//// Creation
//extension AesKey {
//    
//    // MARK: Class's static constructors
//    public class func keystoreWithIdentifier(_ identifier:String,
//                                             data:Data? = nil) -> AesKey
//    {
//        return AesKey(identifier: identifier, data: data)
//    }
//    
//    // MARK: Class's constructors
//    fileprivate convenience init(identifier: String,
//                     data: Data? = nil) {
//        self.init()
//        self.identifier = identifier
//        if let data = data {
//            Keychain.delete(identifier)
//            Keychain.save(identifier, data: data)
//        }
//    }
//}


