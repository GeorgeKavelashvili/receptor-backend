import {
  Injectable,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './dto/auth.dto';
import * as crypto from 'crypto';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService, // Inject ConfigService here
  ) {}

  async hash(password: string) {
    return await bcrypt.hash(password, 10);
  }

  async compare(password: string, hash: string) {
    return await bcrypt.compare(password, hash);
  }

  async signup(dto: AuthDto) {
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: await this.hash(dto.password),
      },
    });
    return this.signToken(user.id, user.email);
  }

  async login(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (!user || !(await this.compare(dto.password, user.password))) {
      throw new ForbiddenException('Incorrect credentials');
    }
    return this.signToken(user.id, user.email);
  }

  async forgotPassword(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

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

    return { message: 'Password reset email sent if user exists' };
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
    if (!user) throw new ForbiddenException('Token invalid or expired');

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

  signToken(id: string, email: string) {
    const payload = { sub: id, email };
    return this.jwt.sign(payload);
  }
}
