"use client";

import {useParams} from "next/navigation";
import {ProfileEditor} from "@/components/config/ProfileEditor";

export default function EditProfilePage() {
    const params = useParams<{ id: string }>();
    const id = params?.id ? decodeURIComponent(params.id) : "";
    return <ProfileEditor profileId={id}/>;
}
