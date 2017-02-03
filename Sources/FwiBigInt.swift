//  Project name: FwiSecurity
//  File name   : FwiBigInt.swift
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

import Foundation
import FwiCore


public struct FwiBigInt: CustomStringConvertible {
    public static let zero = FwiBigInt(withValue: 0)
    public static let one  = FwiBigInt(withValue: 1)
    
    
    // MARK: Class's constructors
    public init() {
        data = Data()
        negative_ = false
    }
    public init(withValue v: Int) {
        self.init(withValue: Int64(v))
    }
    public init(withValue v: UInt) {
        self.init(withValue: UInt64(v))
    }
    public init(withValue v: Int64) {
        self.init()
        var v = v
        
        for _ in 0 ..< MemoryLayout<Int64>.size {
            let b = UInt8(v)
            data.append(b)
            v >>= 8

            // Break condition validation
            if v == -1 {
//                [_data appendBytes:&value length:1];
                data.append(UInt8(bitPattern: -1))
                negative_ = true
                break
            } else if v == 0 {
                break
            }
        }
    }
    public init(withValue v: UInt64) {
        self.init()
        var v = v
        
        for _ in 0 ..< MemoryLayout<UInt64>.size {
            let b = UInt8(v)
            data.append(b)
            v >>= 8
            
            // Break condition validation
            if v == 0 {
                break
            }
        }
        fixData()
    }
    
    public init?(withBigInt bigInt: FwiBigInt?) {
        self.init()
    }
    public init?(withString s: String?, radix r: Int = 10) {
        self.init()
    }
    public init?(withData d: Data?, shouldReverse s: Bool = false) {
        self.init()
    }
    
    // MARK: Class's properties
    public var negative: Bool {
        let sign = data[(data.count - 1)]
        return (sign == 0xff && negative_)
    }
    
    fileprivate var data: Data {
        willSet {
            negative_ = false
            if newValue.count > 1 {
                let sign = newValue[(newValue.count - 1)]
                negative_ = (sign == 0xff)
            }
        }
    }
    fileprivate var negative_: Bool
    
    // MARK: Class's public methods
    public func description(withRadix r: Int) -> String? {
        let radix = (2 <= r && r <= 36 ? r : 10)
        return nil
//        NSMutableString *builder = [[NSMutableString alloc] initWithCapacity:0];
//        __autoreleasing NSString *charSet = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
//    
//        @autoreleasepool {
//        if ([self isEqualTo:[FwiBigInt zero]]) {
//        [builder appendString:@"0"];
//        }
//        else if ([self isEqualTo:[FwiBigInt one]]) {
//        [builder appendString:@"1"];
//        }
//        else {
//        __autoreleasing FwiBigInt *integer  = [FwiBigInt bigIntWithBigInt:self];
//        __autoreleasing FwiBigInt *biRadix  = [FwiBigInt bigIntWithValue:radix];
//        __autoreleasing FwiBigInt *quotient = [FwiBigInt zero];
//        
//        // Validate negative sign
//        if ([self isNegative]) [integer negate];
//        
//        uint8_t *bytes = (void *)[integer.data bytes];
//        while (integer.data.length > 1 || (integer.data.length == 1 && bytes[0] != 0)) {
//        [FwiBigInt _singleByteDivideWithNominator:integer dominator:biRadix quotient:quotient];
//        
//        if (bytes[0] < 10) {
//        [builder insertString:[NSString stringWithFormat:@"%d", bytes[0]]
//        atIndex:0];
//        }
//        else {
//        [builder insertString:[NSString stringWithFormat:@"%c", [charSet characterAtIndex:(bytes[0] - 10)]]
//        atIndex:0];
//        }
//        
//        // Prepare for next loop
//        [integer.data setLength:quotient.data.length];
//        bytes = (void *)[integer.data bytes];
//        
//        memcpy(bytes, quotient.data.bytes, quotient.data.length);
//        [quotient.data clearBytes];
//        [quotient _fixData];
//        }
//        
//        // Apply negative sign
//        if ([self isNegative]) [builder insertString:@"-" atIndex:0];
//        }
//        }
//        
//        __autoreleasing NSString *description = [NSString stringWithFormat:@"%@", [builder description]];
//        FwiRelease(builder);
//        return description;
    }
    
    /// Encode BigInt to data.
    public func encode() -> Data? {
        var d = data
        
        d.reverseBytes()
        return d
    }
    
    /// Encode BigInt to base64 data.
    public func encodeBase64Data() -> Data? {
        return encode()?.encodeBase64Data()
    }
    
    /// Encode BigInt to base64 string.
    public func encodeBase64String() -> String? {
        return encodeBase64Data()?.toString()
    }
    
    // MARK: Class's private methods
    fileprivate func fixData() {
//    const uint8_t *bytes = [_data bytes];
    
//    // Fix data length
//    size_t reduce = 0;
//    for (NSUInteger i = ([_data length] - 1); i >= 1; i--) {
//    if (bytes[i] == 0x00) reduce++;
//    else break;
//    }
//    [_data setLength:([_data length] - reduce)];
    }
    
    // MARK: CustomStringConvertible's members
    public var description: String {
        return ""
    }
}


// MARK: Basic operators
/// Add
public func +(left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    /* Condition validation: add to zero result self */
    guard let right = right, right != FwiBigInt.zero else {
        return left
    }
    
    // Validate negative sign
    switch (left.negative, right.negative) {
    
    // a + (-b) = a - b
    case (false, true):
//        __autoreleasing FwiBigInt *bigIntCopy = [FwiBigInt bigIntWithBigInt:bigInt];
//        [bigIntCopy negate];
//        
//        [self subtract:bigIntCopy];
        break
    
    // (-a) + b = b - a
    case (true, false):
//        __autoreleasing FwiBigInt *bigIntCopy = [FwiBigInt bigIntWithBigInt:bigInt];
//        [self negate];
//        
//        [bigIntCopy subtract:self];
//        FwiRelease(_data);
//        
//        _data = FwiRetain(bigIntCopy.data);
//        _isNegative = [bigIntCopy isNegative];
        break
        
    // (-a) + (-b) = -(a + b)
    case (true, true):
//        __autoreleasing FwiBigInt *bigIntCopy = [FwiBigInt bigIntWithBigInt:bigInt];
//        [bigIntCopy negate];
//        [self negate];
//        
//        [self add:bigIntCopy];
//        [self negate];
        break
    
    // a + b = a + b
    default:
//        // Get data
//        uint8_t *bytes = (void *)[_data bytes];
//        uint8_t *otherBytes = (void *)[bigInt.data bytes];
//        
//        uint8_t c = 0;
//        size_t  length = MAX([_data length], [bigInt.data length]);
//        
//        for (int i = 0; i < length; i++) {
//            // Get byte value at index
//            uint8_t a = (i < [_data length] ? bytes[i] : ([self isNegative] ? 0xff : 0x00));
//            uint8_t b = (i < [bigInt.data length] ? otherBytes[i] : ([bigInt isNegative] ? 0xff : 0x00));
//            
//            // Perform sum at index
//            uint16_t sum = a + b + c;
//            c = (sum & 0xff00) >> 8;
//            
//            // Update value at index
//            if (i < [_data length]) bytes[i] = (uint8_t)(sum & 0x00ff);
//            else [_data appendBytes:&sum length:1];
//        }
//        
//        // Append carry number if there is any left
//        if (c != 0x00) [_data appendBytes:&c length:1];
//        [self _fixData];
        break
    }
    return left
}
public func +=(left: inout FwiBigInt, right: FwiBigInt?) {
    left = left + right
}
public func +(left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func +=(left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left + right
}

/// Subtract
public func -(left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func -=(left: inout FwiBigInt, right: FwiBigInt?) {
    left = left - right
}
public func -(left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func -=(left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left - right
}

/// Multiply
public func *(left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func *=(left: inout FwiBigInt, right: FwiBigInt?) {
    left = left * right
}
public func *(left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func *=(left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left * right
}

/// Divide
public func /(left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func /=(left: inout FwiBigInt, right: FwiBigInt?) {
    left = left / right
}
public func /(left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func /=(left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left / right
}

/// Modulo
public func %(left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func %=(left: inout FwiBigInt, right: FwiBigInt?) {
    left = left % right
}
public func %(left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func %=(left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left % right
}

/// Greater than
public func >(left: FwiBigInt, right: FwiBigInt?) -> Bool {
    guard let right = right else {
        return false
    }
    if left.negative && !right.negative { return false }        // self is negative, bigInt is positive
    else if !left.negative && right.negative { return true }    // self is positive, bigInt is negative
    
    // Same sign
    let length = max(left.data.count, right.data.count)
    for pos in stride(from: length - 1, to: 0, by: -1) {
        let a = (pos < left.data.count ? left.data[pos] : (left.negative ? 0xff : 0x00))
        let b = (pos < right.data.count ? right.data[pos] : (right.negative ? 0xff : 0x00))
        
        if a < b {
            return false
        } else if a > b {
            return true
        }
    }
    return false
}
public func >(left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    guard let left = left else {
        return false
    }
    return left > right
}

/// Less than
public func <(left: FwiBigInt, right: FwiBigInt?) -> Bool {
    guard let right = right else {
        return false
    }
    if left.negative && !right.negative { return true }        // self is negative, bigInt is positive
    else if !left.negative && right.negative { return false }    // self is positive, bigInt is negative
    
    // Same sign
    let length = max(left.data.count, right.data.count)
    for pos in stride(from: length - 1, to: 0, by: -1) {
        let a = (pos < left.data.count ? left.data[pos] : (left.negative ? 0xff : 0x00))
        let b = (pos < right.data.count ? right.data[pos] : (right.negative ? 0xff : 0x00))
        
        if a < b {
            return true
        } else if a > b {
            return false
        }
    }
    return false
}
public func <(left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    guard let left = left else {
        return false
    }
    return left < right
}

/// Equal
public func ==(left: FwiBigInt, right: FwiBigInt?) -> Bool {
    guard let right = right else {
        return false
    }
    return left.data == right.data
}
public func ==(left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    guard let left = left else {
        return false
    }
    return left == right
}

/// Not equal
public func !=(left: FwiBigInt, right: FwiBigInt?) -> Bool {
    guard let right = right else {
        return false
    }
    return left.data != right.data
}
public func !=(left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    guard let left = left else {
        return false
    }
    return left == right
}

/// Greater than or equal
public func >=(left: FwiBigInt, right: FwiBigInt?) -> Bool {
    guard let right = right else {
        return false
    }
    return (left > right || left == right)
}
public func >=(left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    guard let left = left else {
        return false
    }
    return left >= right
}

/// Less than or equal
public func <=(left: FwiBigInt, right: FwiBigInt?) -> Bool {
    guard let right = right else {
        return false
    }
    return (left < right || left == right)
}
public func <=(left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    guard let left = left else {
        return false
    }
    return left <= right
}

// MARK: Bitwise operators
/// AND
public func &(left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func &(left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// OR
public func |(left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func |(left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// XOR
public func ^(left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func ^(left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// Negate
public prefix func !(left: FwiBigInt) -> FwiBigInt {
    return left
}
public prefix func !(left: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// Not
public prefix func ~(left: FwiBigInt) -> FwiBigInt {
    return left
}
public prefix func ~(left: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// Shift left
public func <<(left: FwiBigInt, right: Int) -> FwiBigInt {
    return left
}
public func <<=(left: inout FwiBigInt, right: Int) {
    left = left << right
}
public func <<(left: FwiBigInt?, right: Int) -> FwiBigInt? {
    return left
}
public func <<=(left: inout FwiBigInt?, right: Int) {
    left = left << right
}

/// Shift right
public func >>(left: FwiBigInt, right: Int) -> FwiBigInt {
    return left
}
public func >>=(left: inout FwiBigInt, right: Int) {
    left = left >> right
}
public func >>(left: FwiBigInt?, right: Int) -> FwiBigInt? {
    return left
}
public func >>=(left: inout FwiBigInt?, right: Int) {
    left = left >> right
}
