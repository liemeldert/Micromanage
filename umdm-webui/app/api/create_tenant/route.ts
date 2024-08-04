import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Tenant from "@/models/tenant";
import {auth} from "@/app/auth";
import {generateUrlSafeSecretKey} from "@/lib/utils";

export const POST = auth(async (req) => {
    const session = req.auth;

    if (!session || !session.user || !session.user.id) {
        return NextResponse.json({message: "Not authenticated"}, {status: 401});
    }

    await connectToDatabase();

    try {
        const body = await req.json();
        console.log("Request Body:", body); // Debugging line

        const newTenant = new Tenant({
            ...body,
            members: [session.user.id],
            webhook_secret: generateUrlSafeSecretKey(32),
        });

        await newTenant.save();

        return NextResponse.json(newTenant, {status: 201});
    } catch (error) {
        console.error('Error creating tenant:', error);
        return NextResponse.json({error: 'Error creating tenant'}, {status: 500});
    }
});
