import NextAuth from "next-auth"
import GitHub from "next-auth/providers/github"
import Google from "@auth/core/providers/google";

export const {handlers, signIn, signOut, auth} = NextAuth({
    // providers: [Google],
    providers: [
        GitHub,
        Google
    ],
    callbacks: {
        async signIn({user, account, profile}): Promise<boolean | string> {
            if (account && user) {
                if (!process.env.ALLOWED_USER_EMAILS || (user.email && process.env.ALLOWED_USER_EMAILS?.split(',').includes(user.email.toString()))) {
                    return true;
                } else {
                    return '/auth/not_allowed';
                }
            }

            return false;
        },
        authorized: async ({auth}) => {
            // Logged in users are authenticated, otherwise redirect to login page
            return !!auth
        },

        async session({session, token}: { session: any, token: any }) {
            if (session.user) {
                session.user.id = token.id as string;
                // session.user.isAllowed = (process.env.ALLOWED_USER_IDS ?? '').split(',').includes(token.id as string);
            }
            return session;
        },

        async jwt({token, account}: { token: any, account: any }) {
            if (account) {
                token.id = account.providerAccountId;
            }
            return token;
        },
    },
})