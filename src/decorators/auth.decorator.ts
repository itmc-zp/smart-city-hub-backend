import { applyDecorators, UseGuards } from '@nestjs/common';
import { AuthGuard } from 'src/guards/auth.guards';

export function Authorization() {
  return applyDecorators(
    UseGuards(AuthGuard)
  );
}
