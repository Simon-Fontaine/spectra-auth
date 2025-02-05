export async function sendVerificationEmail(toEmail: string, token: string) {
  console.log(
    `[Mock] Verification link to ${toEmail}: /verify-email?token=${token}`,
  );
}

export async function sendPasswordResetEmail(toEmail: string, token: string) {
  console.log(
    `[Mock] Password reset link to ${toEmail}: /reset-password?token=${token}`,
  );
}
