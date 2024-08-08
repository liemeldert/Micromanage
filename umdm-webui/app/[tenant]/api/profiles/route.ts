    import {NextResponse} from 'next/server';
    import connectToDatabase from '@/lib/mongodb';
    import Profile from '@/models/profile';
    import {auth} from "@/app/auth";

    export const GET = auth(async (req: Request, ctx)=> {
        const tenant = ctx.params?.tenant ?? {}

        await connectToDatabase();

        try {
            const profiles = await Profile.find({tenantId: tenant});
            return NextResponse.json(profiles);
        } catch (error) {
            console.error('Error fetching profiles:', error);
            return NextResponse.json({error: 'Error fetching profiles'}, {status: 500});
        }
    });

    export const POST = auth(async (req: Request, ctx) => {
        const tenant = ctx.params?.tenant ?? {};
        const body = await req.json();

        await connectToDatabase();

        try {
            const profile = await Profile.create({...body, tenantId: tenant});
            return NextResponse.json(profile, {status: 201});
        } catch (error) {
            console.error('Error creating profile:', error);
            return NextResponse.json({error: 'Error creating profile'}, {status: 500});
        }
    });