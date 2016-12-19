// Copyright (c) 2016 BitGo Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rmgutil

const RootThread = ThreadID(0)
const ProvisionThread = ThreadID(1)
const IssueThread = ThreadID(2)

type ThreadID uint8
