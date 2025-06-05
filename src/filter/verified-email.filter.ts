import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  ForbiddenException,
} from '@nestjs/common';
import { Response } from 'express';

@Catch(ForbiddenException)
export class VerifiedEmailFilter implements ExceptionFilter {
  catch(exception: ForbiddenException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    const message = exception.message;

    if (message === 'Please verify your email first.') {
      return response.status(403).json({
        statusCode: 403,
        message: 'You must verify your email before logging in.',
        error: 'Forbidden',
      });
    }

    // For other ForbiddenExceptions, fallback to default message
    return response.status(403).json({
      statusCode: 403,
      message: message || 'Forbidden',
      error: 'Forbidden',
    });
  }
}
