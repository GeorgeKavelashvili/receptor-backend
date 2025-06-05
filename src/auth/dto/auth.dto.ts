import {
  IsEmail,
  IsNotEmpty,
  MinLength,
  IsPhoneNumber,
  Matches,
  ValidateIf,
} from 'class-validator';

export class AuthDto {
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @IsNotEmpty()
  @MinLength(6, { message: 'Password must be at least 6 characters' })
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{6,}$/, {
    message: 'Password must include letters and numbers',
  })
  password: string;
}

export class LoginDto {
  @IsNotEmpty({ message: 'Email or phone is required' })
  identifier: string;

  @IsNotEmpty()
  @MinLength(6)
  password: string;
}

export class SignupDto extends AuthDto {
  @IsNotEmpty({ message: 'First name is required' })
  firstName: string;

  @IsNotEmpty({ message: 'Last name is required' })
  lastName: string;

  @IsNotEmpty({ message: 'Username is required' })
  username: string;

  @IsPhoneNumber('GE', { message: 'Phone number is not valid' })
  phone: string;

  @IsNotEmpty({ message: 'Please confirm your password' })
  confirmPassword: string;
}

export class ResetPasswordDto {
  @IsNotEmpty()
  @MinLength(6)
  password: string;
}
