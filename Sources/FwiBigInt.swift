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

    // MARK: Class's constructors
    public init() {
        data = Data()
        negative_ = false
    }
    public init(withString s: String, radix r: Int) {
        self.init()
    }
    
    // MARK: Class's properties
    public var negative: Bool {
        return false
    }
    fileprivate var data: Data
    fileprivate var negative_: Bool
    
    // MARK: Class's public methods

    // MARK: Class's private methods
    
    // MARK: CustomStringConvertible's members
    public var description: String {
        return ""
    }
}


// MARK: Basic operators
/// Add
public func + (left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func += (left: inout FwiBigInt, right: FwiBigInt?) {
    left = left + right
}
public func + (left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func += (left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left + right
}

/// Subtract
public func - (left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func -= (left: inout FwiBigInt, right: FwiBigInt?) {
    left = left - right
}
public func - (left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func -= (left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left - right
}

/// Multiply
public func * (left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func *= (left: inout FwiBigInt, right: FwiBigInt?) {
    left = left * right
}
public func * (left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func *= (left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left * right
}

/// Divide
public func / (left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func /= (left: inout FwiBigInt, right: FwiBigInt?) {
    left = left / right
}
public func / (left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func /= (left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left / right
}

/// Modulo
public func % (left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func %= (left: inout FwiBigInt, right: FwiBigInt?) {
    left = left % right
}
public func % (left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}
public func %= (left: inout FwiBigInt?, right: FwiBigInt?) {
    left = left % right
}

/// Greater than
public func > (left: FwiBigInt, right: FwiBigInt?) -> Bool {
    return false
}
public func > (left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    return false
}

/// Less than
public func < (left: FwiBigInt, right: FwiBigInt?) -> Bool {
    return false
}
public func < (left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    return false
}

/// Equal
public func == (left: FwiBigInt, right: FwiBigInt?) -> Bool {
    return false
}
public func == (left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    return false
}

/// Greater than or equal
public func >= (left: FwiBigInt, right: FwiBigInt?) -> Bool {
    return false
}
public func >= (left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    return false
}

/// Less than or equal
public func <= (left: FwiBigInt, right: FwiBigInt?) -> Bool {
    return false
}
public func <= (left: FwiBigInt?, right: FwiBigInt?) -> Bool {
    return false
}

// MARK: Bitwise operators
/// AND
public func & (left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func & (left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// OR
public func | (left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func | (left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// XOR
public func ^ (left: FwiBigInt, right: FwiBigInt?) -> FwiBigInt {
    return left
}
public func ^ (left: FwiBigInt?, right: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// Negate
public prefix func ! (left: FwiBigInt) -> FwiBigInt {
    return left
}
public prefix func ! (left: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// Not
public prefix func ~ (left: FwiBigInt) -> FwiBigInt {
    return left
}
public prefix func ~ (left: FwiBigInt?) -> FwiBigInt? {
    return left
}

/// Shift left
public func << (left: FwiBigInt, right: Int) -> FwiBigInt {
    return left
}
public func <<= (left: inout FwiBigInt, right: Int) {
    left = left << right
}
public func << (left: FwiBigInt?, right: Int) -> FwiBigInt? {
    return left
}
public func <<= (left: inout FwiBigInt?, right: Int) {
    left = left << right
}

/// Shift right
public func >> (left: FwiBigInt, right: Int) -> FwiBigInt {
    return left
}
public func >>= (left: inout FwiBigInt, right: Int) {
    left = left >> right
}
public func >> (left: FwiBigInt?, right: Int) -> FwiBigInt? {
    return left
}
public func >>= (left: inout FwiBigInt?, right: Int) {
    left = left >> right
}
