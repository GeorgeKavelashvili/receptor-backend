import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Request } from 'express';
import { AuthGuard } from '../auth/guards/auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: AuthDto) {
    return this.authService.signup(dto);
  }

  @Post('login')
  login(@Body() dto: AuthDto) {
    return this.authService.login(dto);
  }

  @Post('forgot-password')
  forgot(@Body('email') email: string) {
    return this.authService.forgotPassword(email);
  }

  @Post('reset-password')
  reset(@Query('token') token: string, @Body('password') password: string) {
    return this.authService.resetPassword(token, password);
  }

  // ✅ Protected route to get logged-in user info
  @Get('me')
  @UseGuards(AuthGuard)
  getMe(@Req() req: Request) {
    const user = (req as any).user;
    return user;
  }
}
