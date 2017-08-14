/*
 * Wire
 * Copyright (C) 2016 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package com.waz.service

import com.waz.ZLog._
import com.waz.ZLog.ImplicitTag._
import com.waz.threading.Threading
import com.waz.utils.events.{EventContext, Signal, SourceSignal}

import scala.concurrent.Future

trait ZmsLifecycle extends EventContext {
  def active: Signal[Boolean]
  def uiActive: Signal[Boolean]
  def lifecycleState: SourceSignal[LifecycleState]

  def isUiActive: Boolean

  def acquireSync(source: String = ""): Unit
  def acquirePush(source: String = ""): Unit
  def acquireUi(source: String = ""): Unit

  def setLoggedIn(loggedIn: Boolean): Unit

  def releaseSync(source: String = ""): Unit
  def releasePush(source: String = ""): Unit
  def releaseUi(source: String = ""): Unit

  def withSync[Result](body: => Future[Result])(implicit source: LogTag): Future[Result]
  def withPush[Result](body: => Future[Result])(implicit source: LogTag): Future[Result]
  def withUi[Result](body: => Future[Result])(implicit source: LogTag): Future[Result]
}

class ZmsLifecycleImpl extends ZmsLifecycle {
  val lifecycleState = Signal(LifecycleState.Stopped)
  val uiActive = lifecycleState.map(_ == LifecycleState.UiActive)
  def active = lifecycleState.map(st => st == LifecycleState.UiActive || st == LifecycleState.Active)

  val loggedIn = lifecycleState.map(_ != LifecycleState.Stopped)

  private var _loggedIn = false
  private var syncCount = 0
  private var pushCount = 0
  private var uiCount = 0

  def isUiActive = lifecycleState.currentValue.contains(LifecycleState.UiActive)

  def acquireSync(source: String = ""): Unit = acquire('sync, syncCount += 1, source)
  def acquirePush(source: String = ""): Unit = acquire('push, pushCount += 1, source)
  def acquireUi(source: String = ""): Unit = acquire('ui, uiCount += 1, source)

  def setLoggedIn(loggedIn: Boolean) = {
    Threading.assertUiThread()
    _loggedIn = loggedIn
    updateState()
  }

  private def acquire(name: Symbol, action: => Unit, source: String): Unit = {
    Threading.assertUiThread()
    action
    if ((syncCount + pushCount + uiCount) == 1) onContextStart()
    updateState()
    debug(s"acquire${name.name.capitalize}, syncCount: $syncCount, pushCount: $pushCount, uiCount: $uiCount, source: '$source'")
  }

  def releaseSync(source: String = ""): Unit = release('sync, syncCount > 0, syncCount -= 1, source)
  def releasePush(source: String = ""): Unit = release('push, pushCount > 0, pushCount -= 1, source)
  def releaseUi(source: String = ""): Unit = release('ui, uiCount > 0, uiCount -= 1, source)

  def withSync[Result](body: => Future[Result])(implicit source: LogTag = ""): Future[Result] =
    withStateCounter(acquireSync(source), releaseSync(source))(body)

  def withPush[Result](body: => Future[Result])(implicit source: LogTag = ""): Future[Result] =
    withStateCounter(acquirePush(source), releasePush(source))(body)

  def withUi[Result](body: => Future[Result])(implicit source: LogTag = ""): Future[Result] =
    withStateCounter(acquireUi(source), releaseUi(source))(body)

  private def withStateCounter[Result](acquire: => Unit, release: => Unit)(body: => Future[Result]): Future[Result] = {
    import Threading.Implicits.Background
    for {
      _ <- Future(acquire)(Threading.Ui)
      result <- body
      _ <- Future(release)(Threading.Ui)
    } yield result
  }

  private def release(name: Symbol, predicate: => Boolean, action: => Unit, source: String): Unit = {
    Threading.assertUiThread()
    val id = name.name.capitalize
    assert(predicate, s"release$id should be called exactly once for each acquire$id")
    action
    updateState()
    if ((syncCount + pushCount + uiCount) == 0) onContextStop()
    debug(s"release$id syncCount: $syncCount, pushCount: $pushCount, uiCount: $uiCount, source: '$source'")
  }

  private def updateState() = lifecycleState ! {
    if (!_loggedIn) LifecycleState.Stopped
    else if (uiCount > 0) LifecycleState.UiActive
    else if (pushCount > 0) LifecycleState.Active
    else LifecycleState.Idle
  }
}
