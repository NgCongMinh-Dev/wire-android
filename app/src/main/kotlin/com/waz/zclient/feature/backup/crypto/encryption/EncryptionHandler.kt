package com.waz.zclient.feature.backup.crypto.encryption

import com.waz.model.UserId
import com.waz.zclient.core.exception.Failure
import com.waz.zclient.core.exception.IOFailure
import com.waz.zclient.core.functional.Either
import com.waz.zclient.core.functional.flatMap
import com.waz.zclient.core.functional.map
import com.waz.zclient.core.logging.Logger.Companion.verbose
import com.waz.zclient.feature.backup.crypto.Crypto
import com.waz.zclient.feature.backup.crypto.encryption.error.CryptoFailure
import com.waz.zclient.feature.backup.crypto.header.CryptoHeaderMetaData
import java.io.File
import java.io.IOException

class EncryptionHandler(
    private val crypto: Crypto,
    private val cryptoHeaderMetaData: CryptoHeaderMetaData
) {
    fun encryptBackup(backupFile: File, userId: UserId, password: String): Either<Failure, File> =
        try {
            loadCryptoLibrary()
            val salt = crypto.generateSalt()
            writeEncryptedMetaData(salt, userId).flatMap { meta ->
                val backupBytes = backupFile.readBytes()
                encryptWithHash(backupBytes, password, salt).map { encryptedBytes ->
                    return@map File(backupFile.parentFile, backupFile.name + "_encrypted").apply {
                        writeBytes(meta)
                        writeBytes(encryptedBytes)
                    }
                }
            }
        } catch (ex: IOException) {
            Either.Left(IOFailure(ex))
        }

    private fun encryptWithHash(backupBytes: ByteArray, password: String, salt: ByteArray): Either<Failure, ByteArray> =
        crypto.hash(password, salt)?.let { hash ->
            checkExpectedKeySize(hash.size, crypto.encryptExpectedKeyBytes())
            encryptAndCipher(backupBytes, hash)
        } ?: Either.Left(CryptoFailure("Failed to hash account id for backup"))

    private fun encryptAndCipher(backupBytes: ByteArray, hash: ByteArray): Either<Failure, ByteArray>? {
        val header = crypto.streamHeader()
        return crypto.initEncryptState(hash, header)?.let { state ->
            val cipherText = ByteArray(backupBytes.size + crypto.aBytesLength())
            val encrypted = backupBytes + cipherText
            when (val ret: Int = crypto.generatePushMessagePart(state, cipherText, backupBytes)) {
                0 -> Either.Right(encrypted)
                else -> Either.Left(CryptoFailure("Failed to encrypt backup, got code $ret"))
            }
        }
    }

    //This method returns the metadata in the format described here:
    //https://github.com/wearezeta/documentation/blob/master/topics/backup/use-cases/001-export-history.md
    private fun writeEncryptedMetaData(salt: ByteArray, userId: UserId): Either<Failure, ByteArray> =
        crypto.hash(userId.str(), salt)?.let { hash ->
            cryptoHeaderMetaData.writeEncryptedMetaData(salt, hash)
        } ?: Either.Left(CryptoFailure("Failed to hash account id for backup"))

    private fun checkExpectedKeySize(size: Int, expectedKeySize: Int) =
        size.takeIf { it != expectedKeySize }?.let {
            verbose(TAG, "Key length invalid: $it did not match $expectedKeySize")
        }

    private fun loadCryptoLibrary() = crypto.loadLibrary

    companion object {
        const val TAG = "EncryptionHandler"
    }
}
