import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Profile from '@/models/profile';

export async function GET(req: Request, {params}: { params: { tenant: string } }) {
    const {tenant} = params;

    await connectToDatabase();

    try {
        const profiles = await Profile.find({tenantId: tenant});
        return NextResponse.json(profiles);
    } catch (error) {
        console.error('Error fetching profiles:', error);
        return NextResponse.json({error: 'Error fetching profiles'}, {status: 500});
    }
}

export async function POST(req: Request, {params}: { params: { tenant: string } }) {
    const {tenant} = params;
    const body = await req.json();

    await connectToDatabase();

    try {
        const profile = await Profile.create({...body, tenantId: tenant});
        return NextResponse.json(profile, {status: 201});
    } catch (error) {
        console.error('Error creating profile:', error);
        return NextResponse.json({error: 'Error creating profile'}, {status: 500});
    }
}