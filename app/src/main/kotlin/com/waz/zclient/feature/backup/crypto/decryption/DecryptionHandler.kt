package com.waz.zclient.feature.backup.crypto.decryption

import com.waz.model.UserId
import com.waz.zclient.core.exception.Failure
import com.waz.zclient.core.functional.Either
import com.waz.zclient.core.functional.map
import com.waz.zclient.core.logging.Logger
import com.waz.zclient.feature.backup.crypto.Crypto
import com.waz.zclient.feature.backup.crypto.encryption.error.CryptoFailure
import com.waz.zclient.feature.backup.crypto.header.CryptoHeaderMetaData
import com.waz.zclient.feature.backup.crypto.header.TOTAL_HEADER_LENGTH
import java.io.File

class DecryptionHandler(
    private val crypto: Crypto,
    private val cryptoHeaderMetaData: CryptoHeaderMetaData
) {
    fun decryptBackup(backupFile: File, userId: UserId, password: String): Either<Failure, File> {
        loadCryptoLibrary()
        return cryptoHeaderMetaData.readEncryptedMetadata(backupFile)?.let { metaData ->
            crypto.hash(userId.str(), metaData.salt)?.let {
                when (it.contentEquals(metaData.uuidHash)) {
                    true -> decryptBackupFile(password, backupFile, metaData.salt)
                    false -> Either.Left(CryptoFailure("Uuid hashes don't match"))
                }
            } ?: Either.Left(CryptoFailure("Uuid hashing failed"))
        } ?: Either.Left(CryptoFailure("Metadata could not be read"))
    }

    private fun decryptBackupFile(password: String, backupFile: File, salt: ByteArray): Either<Failure, File> {
        val encryptedBackupBytes = ByteArray(TOTAL_HEADER_LENGTH)
        backupFile.inputStream().buffered().read(encryptedBackupBytes)
        return decryptWithHash(encryptedBackupBytes, password, salt).map { decryptedBackupBytes ->
            File.createTempFile("wire_backup", ".zip").apply { writeBytes(decryptedBackupBytes) }
        }
    }

    private fun decryptWithHash(input: ByteArray, password: String, salt: ByteArray): Either<Failure, ByteArray> =
        crypto.hash(password, salt)?.let { key ->
            checkExpectedKeySize(key.size, crypto.decryptExpectedKeyBytes())
            decryptAndCipher(input, key)
        } ?: Either.Left(CryptoFailure("Couldn't derive key from password"))

    private fun decryptAndCipher(input: ByteArray, key: ByteArray): Either<Failure, ByteArray>? {
        val header = input.take(crypto.streamHeaderLength()).toByteArray()
        return crypto.initDecryptState(key, header)?.let { state ->
            val cipherText = input.drop(crypto.streamHeaderLength()).toByteArray()
            val decrypted = ByteArray(cipherText.size + crypto.aBytesLength())
            when (val ret: Int = crypto.generatePullMessagePart(state, decrypted, cipherText)) {
                0 -> Either.Right(decrypted)
                else -> Either.Left(CryptoFailure("Failed to decrypt backup, got code $ret"))
            }
        } ?: Either.Left(CryptoFailure("Failed to init decrypt"))
    }

    private fun checkExpectedKeySize(size: Int, expectedKeySize: Int) =
        size.takeIf { it != expectedKeySize }?.let {
            Logger.verbose(TAG, "Key length invalid: $it did not match $expectedKeySize")
        }

    private fun loadCryptoLibrary() = crypto.loadLibrary

    companion object {
        private const val TAG = "DecryptionHandler"
    }
}
