package com.waz.zclient.shared.backup.datasources.local

import com.waz.zclient.storage.db.conversations.ConversationFoldersDao
import com.waz.zclient.storage.db.conversations.ConversationFoldersEntity
import kotlinx.serialization.Serializable

class ConversationFoldersLocalDataSource(private val conversationFoldersDao: ConversationFoldersDao):
    BackupLocalDataSource<ConversationFoldersEntity, ConversationFoldersJSONEntity>(ConversationFoldersJSONEntity.serializer()) {
    override suspend fun getInBatch(batchSize: Int, offset: Int): List<ConversationFoldersEntity> =
        conversationFoldersDao.getConversationFoldersInBatch(batchSize, offset)

    override fun toJSONType(entity: ConversationFoldersEntity): ConversationFoldersJSONEntity = ConversationFoldersJSONEntity.from(entity)
    override fun toEntityType(json: ConversationFoldersJSONEntity): ConversationFoldersEntity = json.toEntity()
}

@Serializable
data class ConversationFoldersJSONEntity(
    val convId: String = "",
    val folderId: String = ""
) {
    fun toEntity(): ConversationFoldersEntity = ConversationFoldersEntity(
        convId = convId,
        folderId = folderId
    )

    companion object {
        fun from(entity: ConversationFoldersEntity): ConversationFoldersJSONEntity = ConversationFoldersJSONEntity(
            convId = entity.convId,
            folderId = entity.folderId
        )
    }
}
