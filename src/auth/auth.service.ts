// import {
//   Injectable,
//   ForbiddenException,
//   NotFoundException,
// } from '@nestjs/common';
// import { PrismaService } from '../prisma/prisma.service';
// import * as bcrypt from 'bcrypt';
// import { JwtService } from '@nestjs/jwt';
// import { AuthDto, SignupDto, LoginDto } from './dto/auth.dto';
// import * as crypto from 'crypto';
// import * as nodemailer from 'nodemailer';
// import { ConfigService } from '@nestjs/config';

// @Injectable()
// export class AuthService {
//   constructor(
//     private prisma: PrismaService,
//     private jwt: JwtService,
//     private config: ConfigService,
//   ) {}

//   async hash(password: string) {
//     return await bcrypt.hash(password, 10);
//   }

//   async compare(password: string, hash: string) {
//     return await bcrypt.compare(password, hash);
//   }

//   async signup(dto: SignupDto) {
//     const hashedPassword = await this.hash(dto.password);
//     const emailToken = crypto.randomBytes(32).toString('hex');
//     const emailTokenExp = new Date(Date.now() + 1000 * 60 * 60); // 1 hour

//     const user = await this.prisma.user.create({
//       data: {
//         email: dto.email,
//         password: hashedPassword,
//         firstName: dto.firstName,
//         lastName: dto.lastName,
//         username: dto.username,
//         phone: dto.phone,
//         emailVerifyToken: emailToken,
//         emailVerifyTokenExp: emailTokenExp,
//       },
//     });

//     // Send verification email
//     const transporter = nodemailer.createTransport({
//       service: 'gmail',
//       auth: {
//         user: process.env.EMAIL_USER,
//         pass: process.env.EMAIL_PASS,
//       },
//     });

//     await transporter.sendMail({
//       to: dto.email,
//       subject: 'Receptor Email Verification',
//       html: `<a href="http://localhost:3000/auth/verify-email?token=${emailToken}">Verify Email</a>`,
//     });

//     return { message: 'Signup successful, please verify your email' };
//   }

//   async login(dto: LoginDto) {
//     const user = await this.prisma.user.findFirst({
//       where: {
//         OR: [{ email: dto.identifier }, { phone: dto.identifier }],
//       },
//     });

//     if (!user || !(await this.compare(dto.password, user.password))) {
//       throw new ForbiddenException('Incorrect credentials');
//     }

//     if (!user.isVerified) {
//       throw new ForbiddenException('Please verify your email first.');
//     }

//     return this.signToken(user.id, user.email);
//   }

//   async forgotPassword(email: string) {
//     const user = await this.prisma.user.findUnique({ where: { email } });
//     if (!user) throw new NotFoundException('User not found');

//     const token = crypto.randomBytes(32).toString('hex');
//     const expires = new Date(Date.now() + 1000 * 60 * 15); // 15 min

//     await this.prisma.user.update({
//       where: { email },
//       data: { resetToken: token, resetTokenExp: expires },
//     });

//     const transporter = nodemailer.createTransport({
//       service: 'gmail',
//       auth: {
//         user: process.env.EMAIL_USER,
//         pass: process.env.EMAIL_PASS,
//       },
//     });

//     await transporter.sendMail({
//       to: email,
//       subject: 'Receptor Password Reset',
//       html: `<a href="http://localhost:3000/reset-password/${token}">Reset Password</a>`,
//     });

//     return { message: 'Password reset email sent if user exists' };
//   }

//   async resetPassword(token: string, newPassword: string) {
//     const user = await this.prisma.user.findFirst({
//       where: {
//         resetToken: token,
//         resetTokenExp: {
//           gte: new Date(),
//         },
//       },
//     });

//     if (!user) throw new ForbiddenException('Token invalid or expired');

//     const hashed = await this.hash(newPassword);
//     await this.prisma.user.update({
//       where: { id: user.id },
//       data: {
//         password: hashed,
//         resetToken: null,
//         resetTokenExp: null,
//       },
//     });

//     return { message: 'Password reset successfully' };
//   }

//   async verifyEmail(token: string) {
//     const user = await this.prisma.user.findFirst({
//       where: {
//         emailVerifyToken: token,
//         emailVerifyTokenExp: {
//           gte: new Date(),
//         },
//       },
//     });

//     if (!user) throw new ForbiddenException('Token invalid or expired');

//     await this.prisma.user.update({
//       where: { id: user.id },
//       data: {
//         isVerified: true,
//         emailVerifyToken: null,
//         emailVerifyTokenExp: null,
//       },
//     });

//     return { message: 'Email verified successfully' };
//   }

//   signToken(id: string, email: string) {
//     const payload = { sub: id, email };
//     return this.jwt.sign(payload);
//   }
// }
import {
  Injectable,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { AuthDto, SignupDto, LoginDto } from './dto/auth.dto';
import * as crypto from 'crypto';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async hash(password: string) {
    return await bcrypt.hash(password, 10);
  }

  async compare(password: string, hash: string) {
    return await bcrypt.compare(password, hash);
  }

  async signup(dto: SignupDto) {
    const hashedPassword = await this.hash(dto.password);
    const emailToken = crypto.randomBytes(32).toString('hex');
    const emailTokenExp = new Date(Date.now() + 1000 * 60 * 60); // 1 hour

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: hashedPassword,
        firstName: dto.firstName,
        lastName: dto.lastName,
        username: dto.username,
        phone: dto.phone,
        emailVerifyToken: emailToken,
        emailVerifyTokenExp: emailTokenExp,
      },
    });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      to: dto.email,
      subject: 'Receptor Email Verification',
      html: `<a href="http://localhost:3000/auth/verify-email?token=${emailToken}">Verify Email</a>`,
    });

    return { message: 'Signup successful, please verify your email' };
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: dto.identifier }, { phone: dto.identifier }],
      },
    });

    if (!user || !(await this.compare(dto.password, user.password))) {
      throw new ForbiddenException('Incorrect credentials');
    }

    if (!user.isVerified) {
      throw new ForbiddenException('Please verify your email first.');
    }

    return this.signToken(user.id, user.email);
  }

  async forgotPassword(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user)
      throw new NotFoundException(
        'If the email exists, a reset link will be sent',
      );

    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 1000 * 60 * 15); // 15 min

    await this.prisma.user.update({
      where: { email },
      data: { resetToken: token, resetTokenExp: expires },
    });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      to: email,
      subject: 'Receptor Password Reset',
      html: `<a href="http://localhost:3000/reset-password/${token}">Reset Password</a>`,
    });

    return { message: 'If the email exists, a reset link will be sent' };
  }

  async resetPassword(token: string, newPassword: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExp: {
          gte: new Date(),
        },
      },
    });

    if (!user) throw new ForbiddenException('Reset link is invalid or expired');

    const hashed = await this.hash(newPassword);
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashed,
        resetToken: null,
        resetTokenExp: null,
      },
    });

    return { message: 'Password reset successfully' };
  }

  async verifyEmail(token: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        emailVerifyToken: token,
        emailVerifyTokenExp: {
          gte: new Date(),
        },
      },
    });

    if (!user)
      throw new ForbiddenException('Verification link is invalid or expired');

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isVerified: true,
        emailVerifyToken: null,
        emailVerifyTokenExp: null,
      },
    });

    return { message: 'Email verified successfully' };
  }

  signToken(id: string, email: string) {
    const payload = { sub: id, email };
    return this.jwt.sign(payload);
  }
}
