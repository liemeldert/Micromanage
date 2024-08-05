import mongoose from 'mongoose';

const ProfileSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String },
    tenantId: { type: String, required: true },
    profileData: { type: String, required: true }, // Base64 encoded profile data
    type: { type: String, required: true }, // e.g., 'enrollment', 'configuration'
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});

const Profile = mongoose.models.Profile || mongoose.model('Profile', ProfileSchema);

export default Profile;