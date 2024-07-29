import NextAuth from "next-auth"
import Google from "next-auth/providers/google"
import GitHub from "next-auth/providers/github"

export const { handlers, signIn, signOut, auth } = NextAuth({
    // providers: [Google],
    providers: [
        GitHub
    ],
    callbacks: {
        async signIn({ user, account, profile }): Promise<boolean | string> {
            if (account && account.provider === "google") {
                if (((profile?.email_verified ?? false) && profile?.email?.endsWith(process.env.AUTH_GOOGLE_ALLOWED_DOMAIN as string)) ?? false) {
                    return true;
                }
            } 
            else if (account && user) {
                if (user.email && process.env.ALLOWED_USER_EMAILS?.split(',').includes(user.email.toString())) {
                    return true;
                } else {
                    return '/auth/not_allowed';
                }
            }
        
            return false;
        },
        authorized: async ({ auth }) => {
            // Logged in users are authenticated, otherwise redirect to login page
            return !!auth
        },
        // async session({ session, token }: { session: any, token: any }) {
        //   if (session.user) {
        //     session.user.id = token.id as string;
        //     session.user.isAllowed = (process.env.ALLOWED_USER_IDS ?? '').split(',').includes(token.id as string);

        //   }
        //   return session;
        // },
        // async jwt({ token, account }: { token: any, account: any }) {
        //   if (account) {
        //     token.id = account.providerAccountId;
        //   }
        //   return token;
        // },
      },
})