#!/usr/bin/env python
import sqlalchemy as sa
from aiomysql.sa import create_engine
import asyncio
from config import DB_CONFIG


metadata = sa.MetaData()

service = sa.Table(
    'base_service',
    metadata,
    sa.Column('id', sa.Integer, autoincrement=True, primary_key=True),
    sa.Column('name', sa.String(255), nullable=True),
    sa.Column('code', sa.String(255), nullable=True),
    sa.Column('remark', sa.String(255), nullable=True),
    sa.Column('create_time', sa.DateTime, nullable=True),
)

async def register():
    '''
    初始化，获取数据库连接池
    :return:
    '''
    try:
        print("start to connect db!")
        pool = await aiomysql.create_pool(host='192.168.6.120', port=3306,
                                    user='root', password='123456',
                                    db='fuse_nova', charset='utf8')
        print("succeed to connect db!")
        return pool
    except asyncio.CancelledError:
        raise asyncio.CancelledError
    except Exception as ex:
        print("mysql数据库连接失败：{}".format(ex.args[0]))
        return False

async def getCurosr(pool):
    '''
    获取db连接和cursor对象，用于db的读写操作
    :param pool:
    :return:
    '''
    conn = await pool.acquire()
    cur = await conn.cursor()
    return conn, cur

async def close(pool):
    pool.close()
    await pool.wait_closed()
    print("close pool!")
    
async def get_service(loop):
    """
    aiomysql项目地址：https://github.com/aio-libs/aiomysql
    :param loop:
    :return:
    """
    engine = await create_engine(user=DB_CONFIG["DB_USER"], db=DB_CONFIG["DB_NAME"],port=DB_CONFIG["PORT"],
                                 host=DB_CONFIG["DB_HOST"], password=DB_CONFIG["DB_PASS"], loop=loop)
    async with engine.acquire() as conn:
        # await conn.execute(user.insert().values(user_name='user_name01', pwd='123456', real_name='real_name01'))
        # await conn.execute('commit')

        async for row in conn.execute(service.select()):
            print(row.name, row.code)

    engine.close()
    await engine.wait_closed()

# loop = asyncio.get_event_loop()
# loop.run_until_complete(get_service(loop))