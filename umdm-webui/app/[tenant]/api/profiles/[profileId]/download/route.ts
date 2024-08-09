import { NextResponse } from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Profile from '@/models/profile';

export async function GET(req: Request, { params }: { params: { tenant: string, profileId: string } }) {
    const { tenant, profileId } = params;

    await connectToDatabase();

    try {
        const profile = await Profile.findOne({ _id: profileId, tenantId: tenant });

        if (!profile) {
            return NextResponse.json({ error: 'Profile not found' }, { status: 404 });
        }

        // Assuming the profile data is stored in base64 format
        const profileData = Buffer.from(profile.profileData, 'base64');

        // Create a Response object with the profile data
        const response = new NextResponse(profileData);

        // Set the appropriate headers for file download
        response.headers.set('Content-Type', 'application/x-apple-aspen-config');
        response.headers.set('Content-Disposition', `attachment; filename=${profile.name}.mobileconfig`);

        return response;
    } catch (error) {
        console.error('Error downloading profile:', error);
        return NextResponse.json({ error: 'Error downloading profile' }, { status: 500 });
    }
}