package com.waz.zclient.feature.backup.encryption.error

import com.waz.zclient.core.exception.FeatureFailure

data class EncryptionFailure(val msg: String) : FeatureFailure()
