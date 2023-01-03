import {
	BadRequestException,
	Injectable,
	UnauthorizedException
} from '@nestjs/common'
import { InjectModel } from 'nestjs-typegoose'
import { UserModel } from '../user/user.model/user.model'
import { JwtService } from '@nestjs/jwt'
import { AuthDto } from './auth.dto'
import { ModelType } from '@typegoose/typegoose/lib/types'
import { compare, genSalt, hash } from 'bcryptjs'

@Injectable()
export class AuthService {
	constructor(
		@InjectModel(UserModel) private readonly UserModel: ModelType<UserModel>,
		private readonly jwtService: JwtService
	) {}

	async login(dto: AuthDto) {
		const user = await this.validateUser(dto)
		return {
			user: this.returnUserFields(user),
			accessToken: await this.issueAccessToken(String(user._id))
		}
	}

	async register(dto: AuthDto) {
		const oldUser = await this.UserModel.findOne({ email: dto.email })
		if (oldUser) throw new BadRequestException('Такая почта уже существует')

		const salt = await genSalt(10)

		const newUser = new this.UserModel({
			email: dto.email,
			password: await hash(dto.password, salt)
		})

		const user = await newUser.save()

		return {
			user: this.returnUserFields(user),
			accessToken: await this.issueAccessToken(String(user._id))
		}
	}

	async validateUser(dto: AuthDto): Promise<UserModel> {
		const user = await this.UserModel.findOne({ email: dto.email })
		if (!user) throw new UnauthorizedException('Пользователь не найден')

		const isValidPassword = await compare(dto.password, user.password)
		if (!isValidPassword) throw new UnauthorizedException('Неверный пароль')

		return user
	}

	async issueAccessToken(userId: string) {
		const data = { _id: userId }

		return await this.jwtService.signAsync(data, {
			expiresIn: '31d'
		})
	}

	returnUserFields(user: UserModel) {
		return {
			_id: user._id,
			email: user.email
		}
	}
}
