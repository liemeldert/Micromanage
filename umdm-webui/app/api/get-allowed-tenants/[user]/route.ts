import { NextResponse } from "next/server";
import { auth } from "@/app/auth";
import Tenant from '@/models/tenant';
import connectToDatabase from '@/lib/mongodb';

export const GET = auth(async (req, ctx) => {
    const session = req.auth;

    if (!session || !session.user || !session.user.email) {
        return NextResponse.json({ message: "Not authenticated" }, { status: 401 });
    }

    const userId = session.user.email;

    // Connect to the database
    await connectToDatabase();

    try {
        // Find tenants where the user is a member and exclude secrets
        const tenants = await Tenant.find(
            { members: userId },
            '-mdm_secret -webhook_secret' // Exclude sensitive fields
        ).exec();

        // Return the tenants as a JSON response
        return NextResponse.json(tenants);
    } catch (error) {
        console.error('Error fetching tenants:', error);
        return NextResponse.json({ error: 'Error fetching tenants' }, { status: 500 });
    }
});
