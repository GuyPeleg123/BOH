/*
 * Copyright (c) 2019 Robert Falkenberg.
 *
 * This file is part of FALCON 
 * (see https://github.com/falkenber9/falcon).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 */
#include "falcon/common/SignalManager.h"

#include <algorithm>
#include <signal.h>

SignalGate* SignalGate::instance = nullptr;

SignalHandler::SignalHandler() :
  gate(nullptr)
{

}

SignalHandler::~SignalHandler() {
  if(gate != nullptr) {
    gate->detach(*this);
    gate = nullptr;
  }
}

void SignalHandler::registerGate(SignalGate& gate) {
  this->gate = &gate;
}

void SignalHandler::deregisterGate() {
  this->gate = nullptr;
}



SignalGate::SignalGate() :
  handlers()
{

}

void SignalGate::notify() {
  for(std::vector<SignalHandler*>::iterator it = handlers.begin(); it != handlers.end(); ++it) {
    (*it)->handleSignal();
  }
}

SignalGate& SignalGate::getInstance() {
  if(instance == nullptr) {
    instance = new SignalGate();
  }
  return *instance;
}

void SignalGate::signalEntry(int sigNo) {
  // Both Ctrl+C (SIGINT) and standard teardown (SIGTERM — what `timeout`,
  // `kill`, systemd, and Docker send by default) must trigger the same
  // graceful-shutdown path. Without SIGTERM here, those tools fall through
  // to SIGKILL and the libc stdio buffers (pcap, csv, …) are dropped along
  // with everything captured since the last periodic flush.
  if (sigNo == SIGINT || sigNo == SIGTERM) {
    getInstance().notify();
  }
}

SignalGate::~SignalGate() {
  for(std::vector<SignalHandler*>::iterator it = handlers.begin(); it != handlers.end(); ++it) {
    (*it)->deregisterGate();
  }
}

void SignalGate::init() {
  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGTERM);
  sigprocmask(SIG_UNBLOCK, &sigset, nullptr);
  signal(SIGINT,  signalEntry);
  signal(SIGTERM, signalEntry);
}

void SignalGate::attach(SignalHandler& handler) {
  handler.registerGate(*this);
  handlers.push_back(&handler);
}

void SignalGate::detach(SignalHandler& handler) {
  handler.deregisterGate();
  handlers.erase(std::remove(handlers.begin(), handlers.end(), &handler), handlers.end());
}

