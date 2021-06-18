# TCP协议中的RTO计算方式分析


# TCP协议中的RTO计算方式分析

TCP的可靠通信依赖于超时重传机制，重传的时间选择是TCP最复杂的问题之一。超时重传时间设置过长会使得丢包后发送方持续等待，网络空闲时间增大；超时重传时间设置过短会使得超时时很多报文已经到达接收方而只是发送方还没有收到确认，导致很多报文段不必要的重传，使网络负荷增大。

TCP采用了一种自适应算法，依据报文段发送的时间以及收到相应确认的时间计算报文段的往返时间RTT，依此计算超时重传时间RTO。算法如下：

```C
	/* Given a new RTT measurement `RTT' */

	if (RTT is the first measurement made on this connection) {
		SRTT    := RTT
		RTTVAR  := RTT / 2
		RTO	:= SRTT + max(G, 2 * RTT)	/* G is clock granularity in seconds */
	} else {
		delta	:= RTT - SRTT
		SRTT'	:= SRTT  +  1/8 * delta
		RTTVAR' := 3/4 * RTTVAR  +  1/4 * |delta|
		RTO	:= SRTT' + max(G, 4 * RTTVAR')	
	}
```

其中对于SRTT和RTTVAR的计算使用了加权平均的方式，其结果更加平滑。这样的方式也使得越久远的数据对当前结果影响越小，越近的数据对当前结果影响越大，既避免了网络状况抖动对估算结果的影响，又使得该数据尽可能反应当前网络状况。

其中RTO的具体计算方式如上所示为`RTO:= SRTT' + max(G, 4 * RTTVAR')	`。为什么这里会选用4倍的RTTVAR呢？

Linux内核实现中关于这一部分有如下代码：

```C

/* Called to compute a smoothed rtt estimate. The data fed to this 
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge Proceedings
 * SIGCOMM 87]. The algorithm is from the SIGCOMM 88 piece by Van
 * Jacobson.
 * NOTE : the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break it
 * up into three procedures. ——erics
 */
 
static void tcp_rtt_estimator (struct sock *sk, const __u32 mrtt)
{
    struct tcp_sock *tp = tcp_sk(sk);
    long m = mrtt; /*此为得到的新的RTT测量值*/
 
    /* The following amusing code comes from Jacobson's article in
     * SIGCOMM '88. Note that rtt and mdev are scaled versions of rtt and
     * mean deviation. This is designed to be as fast as possible
     * m stands for "measurement".
     * 
     * On a 1990 paper the rto value is changed to :
     * RTO = rtt + 4 * mdev
     *
     * Funny. This algorithm seems to be very broken.
     * These formulae increase RTO, when it should be decreased, increase
     * too slowly, when it should be increased quickly, decrease too quickly
     * etc. I guess in BSD RTO takes ONE value, so that it is absolutely does
     * not matter how to calculate it. Seems, it was trap that VJ failed to 
     * avoid. 8)
     */
    if (m == 0)
        m = 1; /* RTT的采样值不能为0 */
 
    /* 不是得到第一个RTT采样*/
    if (tp->srtt != 0) {
        m -= (tp->srtt >> 3); /* m is now error in rtt est */
        tp->srtt += m; /* rtt = 7/8 rtt + 1/8 new ，更新srtt*/
 
        if (m < 0) { /*RTT变小*/
            m = -m; /* m is now abs(error) */
            m -= (tp->mdev >> 2); /* similar update on mdev */
 
            /* This is similar to one of Eifel findings.
             * Eifel blocks mdev updates when rtt decreases.
             * This solution is a bit different : we use finer gain
             * mdev in this case (alpha * beta).
             * Like Eifel it also prevents growth of rto, but also it
             * limits too fast rto decreases, happening in pure Eifel.
             */
             if (m > 0) /* |err| > 1/4 mdev */
                 m >>= 3;
 
        } else { /* RTT变大 */
            m -= (tp->mdev >> 2); /* similar update on mdev */
        }
 
        tp->mdev += m; /* mdev = 3/4 mdev + 1/4 new，更新mdev */
 
        /* 更新mdev_max和rttvar */
        if (tp->mdev > tp->mdev_max) {
            tp->mdev_max = tp->mdev;
            if (tp->mdev_max > tp->rttvar )
                tp->rttvar = tp->mdev_max;
        }
 
       /* 过了一个RTT了，更新mdev_max和rttvar */
        if (after(tp->snd_una, tp->rtt_seq)) {
            if (tp->mdev_max < tp->rttvar)/*减小rttvar */
                tp->rttvar -= (tp->rttvar - tp->mdev_max) >> 2; 
            tp->rtt_seq = tp->snd_nxt;
            tp->mdev_max = tcp_rto_min(sk); /*重置mdev_max */
        }
 
    } else { 
    /* 获得第一个RTT采样*/
        /* no previous measure. */
        tp->srtt = m << 3; /* take the measured time to be rtt */
        tp->mdev = m << 1; /* make sure rto = 3 * rtt */
        tp->mdev_max = tp->rttvar = max(tp->mdev, tcp_rto_min(sk));
        tp->rtt_seq = tp->snd_nxt; /*设置更新mdev_max的时间*/
    }
}
```

其中提到了

>      * On a 1990 paper the rto value is changed to :
>      * RTO = rtt + 4 * mdev

这里的paper既上文中所提到的Jacobson's article in SIGCOMM '88：即[Congestion Avoidance and Control](http://www.it.uu.se/edu/course/homepage/datakomDVNV/h03/papers/JK88.pdf)。

在该文章的附录C中，作者详细解释了该算法中选取$RTO = rtt + 4 * mdev$的原因。

文章中的符号与代码中的符号有些许差异，这里采用文章中的符号。用R表示往返时延，用V表示偏差。在文章的第一版中采用了$RTO = R + 2 \times V$，之所以改为$RTO = R + 4 \times V$，是由于之前的算法低速链路下存在问题。

为了保证网络的可用性，防止过多的数据注入到网络中致使网络瘫痪，TCP采用了拥塞控制算法，包括慢开始、拥塞避免、快重传和快恢复。这里RTO的计算主要与慢开始阶段有关。

慢开始的思路是当主机开始发送数据时，由于并不清楚网络的负荷情况，如果立刻将大量数据字节注入到网络中，可能引起网络发生拥塞。经验证较好的方法是由小到大的增大发送窗口。为此发送方维持一个叫做拥塞窗口的状态变量，在刚开始通信时为其赋予一个较小的初值，每收到一个对新的报文段的确认后，将拥塞窗口增加刚收到的确认报文段所确认的字节数（小于发送方的最大报文段SMSS）。可以认为在使用慢开始算法后每经过一个传输轮次，拥塞窗口cwnd就加倍。为避免cwnd增长过大引起网络拥塞，需要设置一个慢开始门限ssthresh，如果在慢开始阶段发生了超时重传，则需要将ssthresh设置为当前cwnd的一半。

网络的$总时延=发送时延+传输时延+处理时延+排队时延$。在低速链路下，传输时延相对较小，总时延由发送时延主导，可以近似认为$总时延=发送时延=\frac{数据量}{发送速率}$。当cwnd增加$\Delta w$时，总时延增加约$\Delta R = \frac{\Delta w}{b}$ 。

记慢开始第i个轮次的RTT为$R_i$，偏差为$V_i$，不妨假设$SRTT_i=RTT_i$则有

\\[\begin{align*}
V_i &= R_i - SRTT_i\\ &= R_i - R_{i - 1} \\&= R_i - \frac{R_i}{2}\\&=\frac{R_i}{2}
\end{align*}\\]

如果采用$RTO = R + 2 \times V$，则$RTO_i = R_i + 2 \times \frac{R_i}{2} = 2 R_i = R_{i + 1}$。既超时重传时间等于下一个RTT，并未留有缓冲，这将极大概率导致重传发生。而根据拥塞控制算法的设计，一旦发生重传，ssthresh就要变为当前cwnd的一半，最终的结果为ssthresh迅速减小到0，这将严重影响网络的正常运行。

而采用$RTO = R + 4 \times V$，则$RTO_i = R_i + 4 \times \frac{R_i}{2} = 3 R_i > R_{i + 1}$。此时超时重传时间大于下一个RTT，避免了在慢开始阶段因算法设计缺陷导致的重传和网络故障。

## 参考文献

\[1\][Congestion Avoidance and Control ](https://www.cs.auckland.ac.nz/courses/compsci742s2c/resources/congavoid.pdf)

\[2\]计算机网络 第7版 谢希仁

