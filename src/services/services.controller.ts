import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Query, UseInterceptors, UploadedFile, UploadedFiles, HttpException, HttpStatus } from '@nestjs/common';
import { ServicesService } from './services.service';
import { CreateServiceDto } from './dto/create-service.dto';
import { UpdateServiceDto } from './dto/update-service.dto';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { Role } from 'src/auth/enums/role.enum';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express';
import { ApiTags, ApiBearerAuth, ApiBody, ApiConsumes, ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiParam, ApiQuery, ApiUnauthorizedResponse, ApiNotFoundResponse, ApiInternalServerErrorResponse, ApiForbiddenResponse } from '@nestjs/swagger';
import { User } from 'src/users/entities/user.entity';

@ApiTags('services')
@Controller('services')
export class ServicesController {
  constructor(private readonly servicesService: ServicesService) {}

  @Post()
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(Role.Admin)
  @ApiBearerAuth()
  @ApiBody({ type: CreateServiceDto })
  @ApiCreatedResponse({ description: 'The service has been successfully created.' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized.' })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  @ApiInternalServerErrorResponse({ description: 'Internal Server Error.' })
  async create(@Body() createServiceDto: CreateServiceDto, @User() user: User) {
    return await this.servicesService.create(createServiceDto, user);
  }

  @Get()
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(Role.Admin)
  @ApiBearerAuth()
  @ApiOkResponse({ description: 'The services have been successfully retrieved.' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized.' })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  @ApiInternalServerErrorResponse({ description: 'Internal Server Error.' })
  findAll(@Query('page') page: number, @Query('limit') limit: number) {
    return this.servicesService.findAll(page, limit);
  }

  @Get(':id')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(Role.Admin)
  @ApiBearerAuth()
  @ApiParam({ name: 'id', description: 'The id of the service.' })
  @ApiOkResponse({ description: 'The service has been successfully retrieved.' })
  @ApiNotFoundResponse({ description: 'Service not found.' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized.' })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  @ApiInternalServerErrorResponse({ description: 'Internal Server Error.' })
  findOne(@Param('id') id: string) {
    return this.servicesService.findOne(id);
  }

  @Patch(':id')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(Role.Admin)
  @ApiBearerAuth()
  @ApiParam({ name: 'id', description: 'The id of the service.' })
  @ApiBody({ type: UpdateServiceDto })
  @ApiOkResponse({ description: 'The service has been successfully updated.' })
  @ApiNotFoundResponse({ description: 'Service not found.' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized.' })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  @ApiInternalServerErrorResponse({ description: 'Internal Server Error.' })
  async update(@Param('id') id: string, @Body() updateServiceDto: UpdateServiceDto, @User() user: User) {
    return await this.servicesService.update(id, updateServiceDto, user);
  }

  @Delete(':id')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(Role.Admin)
  @ApiBearerAuth()
  @ApiParam({ name: 'id', description: 'The id of the service.' })
  @ApiOkResponse({ description: 'The service has been successfully deleted.' })
  @ApiNotFoundResponse({ description: 'Service not found.' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized.' })
  @ApiForbiddenResponse({ description: 'Forbidden.' })
  @ApiInternalServerErrorResponse({ description: 'Internal Server Error.' })
  remove(@Param('id') id: string, @User() user: User) {
    return this.servicesService.remove(id, user);
  }
}
