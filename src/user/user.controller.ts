import { Body, Controller, Get, HttpCode, HttpStatus, Param, Patch, Query } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiExcludeEndpoint,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags
} from '@nestjs/swagger';
import { Authorization } from 'src/decorators/auth.decorator';
import { Authorized } from 'src/decorators/authorized.decorator';
import { UpdateUserDto } from './dto/update.user.dto';
import { UserDto } from './dto/user.dto';
import { UserService } from './user.service';

@ApiTags('Користувач - (у розробці)')
@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Authorization()
  @HttpCode(HttpStatus.OK)
  @Get('profile')
  @ApiOperation({ summary: 'Отримати профіль користувача' })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, type: UserDto })
  public async findProfile(@Authorized('id') userId: string ){
    return this.userService.findById(userId)
  }

  @HttpCode(HttpStatus.OK)
  @Get('by-id/:id')
  @ApiOperation({ summary: 'Отримати користувача за ID' })
  @ApiParam({ name: 'id', description: 'ID користувача' })
  @ApiResponse({ status: 200, type: UserDto })
  public async findById(@Param('id') id: string) {
    return this.userService.findById(id)
  }

  @Authorization()
  @HttpCode(HttpStatus.OK)
  @Patch('profile')
  @ApiOperation({ summary: 'Оновити профіль користувача' })
  @ApiBearerAuth()
  @ApiBody({ type: UpdateUserDto })
  @ApiResponse({ status: 200, type: UpdateUserDto  })
  public async updateProfile(@Authorized('id') userId: string, @Body() dto: UpdateUserDto ){
    return this.userService.update(userId, dto)
  }

  @Get('method')
  @ApiExcludeEndpoint()
  async getMethodByEmail(@Query('email') email: string) {
    const user = await this.userService.findByEmail(email);

    return {
      method: user?.method ?? null, 
    };
  }

}