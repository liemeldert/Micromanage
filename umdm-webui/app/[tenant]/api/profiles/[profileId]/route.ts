import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Device from '@/models/device';
import Profile from '@/models/profile';

export async function GET(req: Request, {params}: { params: { tenant: string, profileId: string } }) {
    const {tenant, profileId} = params;

    await connectToDatabase();

    try {
        const devices = await Device.find({tenantId: tenant, profiles: profileId});
        return NextResponse.json(devices);
    } catch (error) {
        console.error('Error fetching devices with profile:', error);
        return NextResponse.json({error: 'Error fetching devices with profile'}, {status: 500});
    }
}

export async function DELETE(req: Request, { params }: { params: { tenant: string, profileId: string } }) {
    const { tenant, profileId } = params;

    await connectToDatabase();

    try {
        const result = await Profile.deleteOne({ _id: profileId, tenantId: tenant });
        if (result.deletedCount === 0) {
            return NextResponse.json({ error: 'Profile not found' }, { status: 404 });
        }
        return NextResponse.json({ message: 'Profile deleted successfully' });
    } catch (error) {
        console.error('Error deleting profile:', error);
        return NextResponse.json({ error: 'Error deleting profile' }, { status: 500 });
    }
}
