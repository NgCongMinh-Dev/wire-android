package com.waz.zclient.feature.backup.crypto.encryption.error

import com.waz.zclient.core.exception.FeatureFailure

data class CryptoFailure(val msg: String) : FeatureFailure()
