package com.virgilsecurity.purekit.pure;

public interface PureStorage {
    void insertUser(UserRecord userRecord);
    void updateUser(UserRecord userRecord);
    UserRecord selectUser(String userId);
    UserRecord[] selectUsers(int pheRecordVersion);
    CellKey selectKey(String userId, String dataId);
    void insertKey(String userId, String dataId, byte[] cpk, byte[] encryptedCsk);
    void updateKey(String userId, String dataId, byte[] encryptedCsk);
}
