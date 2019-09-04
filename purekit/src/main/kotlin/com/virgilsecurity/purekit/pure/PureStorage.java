package com.virgilsecurity.purekit.pure;

public interface PureStorage {
    void insertUser(UserRecord userRecord);
    void updateUser(UserRecord userRecord);
    UserRecord selectUser(String userId);
    UserRecord[] selectUsers(int pheRecordVersion);
}
