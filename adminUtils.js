// Add this to your firebase.js or adminUtils.js file
export const awardPointsManually = async (username, points, taskId, taskDescription) => {
    try {
        const usersRef = db.collection('users');
        const userDoc = usersRef.doc(username);

        // Create the action ID from the taskId
        const actionId = `${taskId.startsWith('retweet_') ? 'retweet' : 'task'}_${Date.now()}`;

        await userDoc.set({
            username: username,
            actions: {
                [actionId]: true,
                lastUpdated: FieldValue.serverTimestamp(),
                points: FieldValue.increment(points)
            }
        }, { merge: true });

        return true;
    } catch (error) {
        console.error("Error awarding points manually:", error);
        throw error;
    }
};

// Add this to your adminUtils.js file
export const getAllUsers = async () => {
    try {
        const usersRef = db.collection('users');
        const snapshot = await usersRef.get();
        
        return snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                id: doc.id,
                username: data.username,
                points: data.actions?.points || 0,
                lastUpdated: data.actions?.lastUpdated?.toDate() || null
            };
        });
    } catch (error) {
        console.error("Error fetching users:", error);
        throw error;
    }
};