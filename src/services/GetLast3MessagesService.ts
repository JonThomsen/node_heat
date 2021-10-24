import prismaClient from "../prisma";

class GetLast3MessagesService {
  async execute() {
    const messages = await prismaClient.message.findMany({
      take: 3, //3 últimas mensagens
      orderBy: {
        created_at: "desc"
      },
      include: {
        user: true
      }
    })

    // select * from messages limit 3 order by created_at desc
    return messages;
  }
}


export { GetLast3MessagesService };