/*
 * YaoWire.h
 *
 */

#ifndef YAO_YAOWIRE_H_
#define YAO_YAOWIRE_H_

#include "BMR/Key.h"
#include "BMR/Register.h"

class YaoWire : public Phase
{
	friend ostream& operator<<(ostream&, const YaoWire&);

protected:
	Key key_;

public:
	static int threshold(int) { return 1; }

	template<class T>
	static void xors(GC::Processor<T>& processor, const ArgVector& args);
	template<class T>
	static void xors(GC::Processor<T>& processor, const ArgVector& args,
			size_t start, size_t end);

	template<class T>
	static void andm(GC::Processor<T>& processor,
			const BaseInstruction& instruction);

	void XOR(const YaoWire& left, const YaoWire& right)
	{
		key_ = left.key_ ^ right.key_;
	}

	template<class T>
	void other_input(T&, int) {}
};

inline ostream& operator<<(ostream& o, const YaoWire& wire)
{
    o << wire.key_;
	return o;
}

#endif /* YAO_YAOWIRE_H_ */
