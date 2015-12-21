#!/usr/local/bin/python
# coding: utf-8

#-----------------------------------------------------------------------------
#-- Элементарный ips, написанный на Python. Запускать под sudo
#-- 
#-- Разработано Егором Маховым george.mahoff@gmail.com
#-- 
#-- Скрипт работает как система обнаружения/предтвращения вторежний, 
#-- которая выполняет следующие задачи:
#-- 1) мониторит логи различных сервисов, заданные в конфиге
#-- 2) считает количество попыток, предпринятых с опр. IP адреса и при 
#-- превышении банит посредством правила iptables на опр. время
#-- 3) Разбанивает пользователей по истечению опр. времени
#-- 4) Обнаруживает попытки медленного брутфорса

import pyinotify, re, os, threading, argparse, time
from ConfigParser import SafeConfigParser
from collections import defaultdict

# Глобальные переменные
CONNLIST = []		# Список соединений
THREADS = []		# Список активных тредов
SERVICES = defaultdict()# Мэп сервисов (лог, ключевое слов)
UNBAN_TIME = 60		# Время до разбана
MAX_ATTEMPTS = 3	# Количество попыток до бана
ATTEMPT_RESET_TIME = 60 # Время до сброса количества попыток
SLOW_SCAN_TIME = 30	# Время ожидания для подозрения на медленный брутфорс

# Конфиг файл
CFG_NAME = "config"

#-----------------------------------------------------------
#-- Обрабатывает ивенты от pyinotify
class EventHandler(pyinotify.ProcessEvent):

	#---------------------------------------------------------------------
	#-- event - Содержит инфомацию об ивенте
	#--
	#-- Когда случается событие "IN_MODIFY", функция обрабатывает
	#-- попытку через поиск ключевого слова из последней строки лога
	#-- и запускает функцию обработки если находит совпадение
	def process_IN_MODIFY(self, event):
		line = None
		for service, attr in SERVICES.iteritems():
			if event.pathname == attr[1]:
				line = get_last_lines(attr[1], attr[0])
				if line is not None:
					# Рег.выражения для IP адреса
					ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)[0]
					if ip is not None:
						handle_attempt(ip, service)

#-----------------------------------------------------------------
#-- ip - IP соединения
#-- reset_timer - Таймер сброса
#-- odd_attempts - Количество подозрительных попыток
#-- prev_attempt - Время предыдущей попытки
#--
#-- Класс, который обрабатывает каждое проваленное соединение обнаруженное 
#-- системой
class Connections:
	def __init__(self, ip, attempts=None):
		self.ip = ip
		self.reset_timer = 0
		self.odd_attempts = 0
		self.prev_attempt = time.time()

		if attempts is None:
			self.attempts = {}
		else:
			self.attempts = attempts

		# Инициализация кол-ва попыток
		for service in SERVICES:
			self.attempts[service] = 0

	#-----------------------------------------------------------------------
	#-- service - Тип сервиса
	#--
	#-- Обрабатывает неудачную попытку получить доступ к сервису по данному 
	#-- соединению. Если пользователь делает попытки через большие 	
	#-- промежутки времене (больше чем обычные попытки, но меньше чем если
	#-- бы он уже подключился или сдался (2 часа в стандартных настройках))
	#-- то увеличиваем уровень подозрения. Если уровень подозрения достигает
	#-- значения 3, то баним пермаментно.
	#-- В противном случае, проверяем превысил ли он максимально допустимое
	#-- количество попыток. Если да, то баним на опр. время. 
	#-- Количество попыток сбрасывается через опр. промежуток времени.
	def failed_attempt(self, service):
		self.attempts[service] += 1
		previous_attempt_elapse = time.time() - self.prev_attempt
		self.prev_attempt = time.time()
		if previous_attempt_elapse >= SLOW_SCAN_TIME and previous_attempt_elapse < 7200:
			self.odd_attempts += 1
			if self.odd_attempts >= 3:
				ban_ip(self.ip, service, 1) # бан навсегда
				print "Бан %s в %s по подозрению в медленном брутфорсе" % (self.ip, service)
				return

		# Если количество попыток превысило MAX_ATTEMPTS - бан
		if self.attempts[service] == MAX_ATTEMPTS:
			ban_ip(self.ip, service)
			print "Бан %s в %s" % (self.ip, service)
			self.attempts[service] = 0
		# в противном случае запускает таймер на сброса кол-ва попыток
		elif self.reset_timer == 0:
			reset_thread = threading.Timer(ATTEMPT_RESET_TIME, self.reset_attempts, args=[service,]).start()
			THREADS.append(reset_thread)
			self.reset_timer = 1

	#--------------------------------------------------------
	#-- service - тип сервиса
	#-- Сбрасывает количество попыток
	def reset_attempts(self, service):
		print "Сброс попыток для %s в %s" % (self.ip, service)
		self.attempts[service] = 0
		self.reset_timer = 0

#-----------------------------------------------------------------------------
#-- ip - IP попытки
#-- service - тип сервиса (ssh, ftp, итд)
#-- Определяет надо ли создать новое соединение или обновить существующие
def handle_attempt(ip, service):
	print "Отказ в доступе адресу %s в сервисе %s" % (ip, service)
	# если список пустой
	if len(CONNLIST) == 0:
		conn = Connections(ip)
		conn.failed_attempt(service)
		CONNLIST.append(conn)
	else:
		append = 0
		# если можем найти в списке связей
		for conn in CONNLIST:
			if conn.ip == ip:
				append = 1
				conn.failed_attempt(service)
				break
		# если не можем то дабавляем с список
		if append == 0:
			conn = Connections(ip)
			conn.failed_attempt(service)
			CONNLIST.append(conn)

#-----------------------------------------------------------------------------
#-- ip - внешний ip адрес, который надо забанить
#-- service - тип сервиса
#-- Функция берет входной ip и сервис и банит в нетфильтре. После чего 
#-- запускает тред (если время разбана != 0) с таймером, по истечению которого #-- произойдет разбан
def ban_ip(ip, service, forever=0):
	os.system("iptables -A INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))
	if UNBAN_TIME != 0 and forever == 0:
		unban_timer = threading.Timer(UNBAN_TIME, unban_ip, args=[ip, service,]).start()
		THREADS.append(unban_timer)

#-----------------------------------------------------------------------------
#-- ip - внешний ip адрес, который надо разбанить
#-- service - тип сервиса
#-- Функция берет ip и сервис и разбанивает его через netfilter iptables
def unban_ip(ip, service):
	print "ip %s разбанен в %s" % (ip, service)
	os.system("iptables -D INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))

#-----------------------------------------------------------------------------
#-- Функция создает обьект configParser и парсит конфиг, чтобы достать сервис и 
#-- связанные с ним путь и ключевое слова
def load_cfg():
	cfg_parser = SafeConfigParser()
	cfg_parser.read(CFG_NAME)

	for sections in cfg_parser.sections():
		for variable, value in cfg_parser.items(sections):
			if variable == "keyword":
				keyword = value
				print value
			elif variable == "file":
				filepath = value
		SERVICES[sections] = [keyword, filepath]

#-----------------------------------------------------------------------------
#-- file - лог файл
#-- keyword - искомый набор слов
#-- Функция идет в конец файла и возращает строку, содержащую ключевое слово
def get_last_lines(logfile, keyword):
	with open(logfile, "r") as f:
		f.seek(0, 2) # идем к концу
		fsize = f.tell() # получаем текущую позицию
		f.seek(max(fsize-1024, 0), 0)
		lines = f.readlines()
	lines = lines[-1:] # читаем 1 строку до
	for line in lines:
		if keyword in line:
			return line

#-----------------------------------------------------------------------------
#-- Main функция программы
#-- Создает Watch manager и notifier и наблюдает за file_events
def main():
	load_cfg() # Загрузка конфига

	wm = pyinotify.WatchManager()
	handler = EventHandler()

	file_events = pyinotify.IN_MODIFY  # Наблюдение за MODIFY
	notifier = pyinotify.Notifier(wm, handler)

	for service, attr in SERVICES.iteritems():
		print "Наблюдение за %s..." % attr[1]
		wm.add_watch(attr[1], file_events)
	print "-- У каждого IP-адреса есть %s попыток,чтобы подкочиться к сервису" % MAX_ATTEMPTS
	print "-- Количество попыток сбрасывается каждые %s секунд" % ATTEMPT_RESET_TIME
	print "-- Slow таймер установлен на %s секунд" % SLOW_SCAN_TIME
	if UNBAN_TIME != 0:
		print "-- IP будут разбанены после %s секунд" % UNBAN_TIME
	else:
		print "-- Забаненные IP-адреса не будут автоматически разбанены"
	print "Защита запущена..."
	notifier.loop()

# Проверка на main в рантайме
if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		for thread in THREADS:
			thread.cancel() # выключение оставшихся таймеров
