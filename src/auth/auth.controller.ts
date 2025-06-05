// import {
//   Body,
//   Controller,
//   Get,
//   Post,
//   Query,
//   Req,
//   UseGuards,
//   UsePipes,
//   ValidationPipe,
//   BadRequestException,
// } from '@nestjs/common';
// import { AuthService } from './auth.service';
// import { AuthDto, ResetPasswordDto, SignupDto, LoginDto } from './dto/auth.dto';
// import { Request } from 'express';
// import { AuthGuard } from '../auth/guards/auth.guard';

// @Controller('auth')
// export class AuthController {
//   constructor(private authService: AuthService) {}

//   @Post('signup')
//   @UsePipes(new ValidationPipe({ whitelist: true }))
//   async signup(@Body() dto: SignupDto) {
//     if (dto.password !== dto.confirmPassword) {
//       throw new BadRequestException('Passwords do not match');
//     }
//     return this.authService.signup(dto);
//   }

//   @Post('login')
//   @UsePipes(new ValidationPipe({ whitelist: true }))
//   login(@Body() dto: LoginDto) {
//     return this.authService.login(dto);
//   }

//   @Post('forgot-password')
//   @UsePipes(new ValidationPipe({ whitelist: true }))
//   forgot(@Body('email') email: string) {
//     return this.authService.forgotPassword(email);
//   }

//   @Post('reset-password')
//   @UsePipes(new ValidationPipe({ whitelist: true }))
//   reset(@Query('token') token: string, @Body() dto: ResetPasswordDto) {
//     return this.authService.resetPassword(token, dto.password);
//   }

//   @Get('verify-email')
//   async verifyEmail(@Query('token') token: string) {
//     return this.authService.verifyEmail(token);
//   }

//   @Get('me')
//   @UseGuards(AuthGuard)
//   getMe(@Req() req: Request) {
//     const user = (req as any).user;
//     return user;
//   }
// }
import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  UseGuards,
  UsePipes,
  ValidationPipe,
  BadRequestException,
  UseFilters,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto, ResetPasswordDto, SignupDto, LoginDto } from './dto/auth.dto';
import { Request } from 'express';
import { AuthGuard } from '../auth/guards/auth.guard';
import { VerifiedEmailFilter } from '../filter/verified-email.filter';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  async signup(@Body() dto: SignupDto) {
    if (dto.password !== dto.confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }
    return this.authService.signup(dto);
  }

  @Post('login')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  @UseFilters(VerifiedEmailFilter) // 👈 Added filter here
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('forgot-password')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  forgot(@Body('email') email: string) {
    return this.authService.forgotPassword(email);
  }

  @Post('reset-password')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  reset(@Query('token') token: string, @Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(token, dto.password);
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string) {
    return this.authService.verifyEmail(token);
  }

  @Get('me')
  @UseGuards(AuthGuard)
  getMe(@Req() req: Request) {
    const user = (req as any).user;
    return user;
  }
}
